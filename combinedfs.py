#!/usr/bin/env python3

import os
import re
import sys
import stat
import yaml
import errno

# Excerpt from `apt show python3-fusepy`:
#   Due to a name clash with the existing API-incompatible python-fuse package,
#   the importable module name for fusepy in Debian is 'fusepy' instead of
#   upstream's 'fuse'.
try:
	from fusepy import FUSE, FuseOSError, Operations
except ImportError:
	from fuse import FUSE, FuseOSError, Operations

DEFAULT_ROOT = '/etc/letsencrypt/live'
DEFAULT_CERT_FILTER = False
DEFAULT_WHITELIST = True
DEFAULT_CERT_PATTERN = '.'
DEFAULT_SEPARATOR = '/' 
DEFAULT_SENSITIVE_PATTERN = '/privkey.pem$'
TIME_PROPS = ('st_atime', 'st_ctime', 'st_mtime')

class CombinedFS(Operations):
	def __init__(self, conf):
		self.root = conf.get('letsencrypt_live', DEFAULT_ROOT)
		self.filter = conf.get('cert_filter', DEFAULT_CERT_FILTER)
		self.whitelist = conf.get('cert_whitelist', DEFAULT_WHITELIST)
		self.pattern = conf.get('cert_pattern', DEFAULT_CERT_PATTERN)
		self.separator = conf.get('separator', DEFAULT_SEPARATOR)
		self.files = conf.get('files', {})
		self.sensitive_pattern = conf.get('sensitive_pattern', DEFAULT_SENSITIVE_PATTERN)
		self.filedesc_index = 0
		self.filedesc = {}
		# Compile regexes:
		self.sensitive_pattern_re = re.compile(self.sensitive_pattern)
		if self.filter:
			self.pattern_re = re.compile(self.pattern)

	# Helpers:

	def filter_cert(self, cert):
		if not self.filter:
			return True
		return bool(self.pattern_re.match(cert)) == self.whitelist

	def read_only(self):
		raise FuseOSError(errno.EROFS)

	def _full_path(self, partial):
		if partial.startswith("/"):
			partial = partial[1:]
		path = os.path.join(self.root, partial)
		return path

	def get_paths(self, cert, file_spec):
		return self.expand_paths(cert, file_spec.get('content', []))

	def is_sensitive_file(self, filepath):
		return self.sensitive_pattern_re.search(filepath)

	def expand_paths(self, cert, paths):
		expanded_paths = []
		for path in paths:
			path = path.replace('${cert}', cert)
			if not path.startswith('/'):
				path = os.path.join(self.root, cert, path)
			expanded_paths.append(path)
		return expanded_paths

	def attributes(self, full_path):
		st = os.lstat(full_path)
		return dict((key, getattr(st, key)) for key in ('st_atime', 'st_ctime',
		      'st_gid', 'st_mode', 'st_mtime', 'st_nlink', 'st_size', 'st_uid'))

	def analyse_path(self, path):
		"""
		Return a tuple of three values reflecting what the given path points to.
		Raise a FuseOSError with ENOENT if the path does not match anything.
		The three values are:
		  cert: the target certificate; None only for the root directory;
		  filename: the requested filename; None only for:
		    - the root directory;
		    - the cert-specific directory when '/' is used as separator;
		  file_spec: the specification for the requested filename.
		"""
		# Initial values:
		cert = None
		filename = None
		file_spec = None
		# Root directory:
		if path == '/':
			return cert, filename, file_spec
		# cert and flilename:
		path_components = path[1:].split('/')
		if self.separator == '/':
			if len(path_components) > 2:
				raise FuseOSError(errno.ENOENT)
			cert = path_components[0]
			if len(path_components) == 2:
				filename = path_components[1]
		else:
			if len(path_components) != 1:
				raise FuseOSError(errno.ENOENT)
			components = path_components[0].split(self.separator)
			if len(components) != 2:
				raise FuseOSError(errno.ENOENT)
			cert = components[0]
			filename = components[1]
		# Ensure cert is not filtered out:
		if not self.filter_cert(cert):
			raise FuseOSError(errno.ENOENT)
		# file_spec:
		if filename is not None:
			try:
				file_spec = self.files[filename]
			except KeyError:
				raise FuseOSError(errno.ENOENT)
		return cert, filename, file_spec

	# Filesystem methods

	def access(self, path, mode):
		"""
		libfuse documentation states:
		  This will be called for the access() system call. If the
		  'default_permissions' mount option is given, this method is not called.
		Since this program enforces default_permissions, this method will never
		be called, which makes it dead simple to implement.
		"""
		pass

	def getattr(self, path, fh=None):
		cert, filename, file_spec = self.analyse_path(path)
		if filename is None: # Directory
			dir_attrs = self.attributes(self._full_path(path))
			dir_attrs['st_mode'] = stat.S_IFDIR | 0o555
			return dir_attrs
		attrs = {
			'st_nlink': 1,
			'st_uid': file_spec.get('uid', 0),
			'st_gid': file_spec.get('gid', 0),
			# By default, files are considered public and thus world-readable:
			'st_perm': 0o444,
			'st_size': 0,
		}
		paths = self.get_paths(cert, file_spec)
		if not paths:
			# Virtual empty file:
			root_stats = os.stat(self.root)
			for prop in TIME_PROPS:
				attrs[prop] = getattr(root_stats, prop)
			attrs['st_mode'] = stat.S_IFREG | attrs['st_perm']
			return attrs
		stats = {}
		for filepath in paths:
			try:
				# DO follow symlinks (stat vs lstat):
				stats[filepath] = os.stat(filepath)
			except OSError as ose:
				raise FuseOSError(ose.errno)
		for filepath, stat_obj in stats.items():
			# Pick the highest/latest value for access/change/modification times:
			for prop in TIME_PROPS:
				prop_val = getattr(stat_obj, prop)
				if prop_val > attrs.get(prop, 0):
					attrs[prop] = prop_val
			# Add up sizes:
			attrs['st_size'] += stat_obj.st_size
			# Lower permissions if necessary:
			if self.is_sensitive_file(filepath):
				attrs['st_perm'] = 0o400
		attrs['st_mode'] = stat.S_IFREG | attrs['st_perm']
		return attrs

	def readdir(self, path, fh):
		cert, filename, _ = self.analyse_path(path)
		# Deal only with directories:
		if filename:
			raise FuseOSError(errno.ENOTDIR)
		# Yield common directory entries:
		yield '.'
		yield '..'
		if not cert:
			# Top-level directory
			flat_mode = self.separator != '/'
			for cert in (d for d in os.listdir(self.root) if self.filter_cert(d)):
				if flat_mode:
					for filename in self.files:
						yield cert + self.separator + filename
				else:
					yield cert
		else:
			# Second-level directory
			for filename in self.files:
				yield filename

	def open(self, path, flags):
		cert, filename, file_spec = self.analyse_path(path)
		if not cert or not filename:
			raise FuseOSError(errno.ENOENT)
		# FIXME take flags into account
		# FIXME the code below feels unsafe
		self.filedesc_index += 1
		self.filedesc[self.filedesc_index] = {
			'cert': cert,
			'filename': filename,
			'file_spec': file_spec,
		}
		return self.filedesc_index

	def read(self, path, length, offset, fh):
		filedesc = self.filedesc[fh]
		data = filedesc.get('data')
		if data is None:
			data = bytes([])
			paths = self.get_paths(filedesc['cert'], filedesc['file_spec'])
			for path in paths:
				with open(path, 'rb') as path_fd:
					data += path_fd.read()
			filedesc['data'] = data
		read_chunk = data[offset:offset + length]
		return read_chunk

	def release(self, path, fh):
		# FIXME reset self.filedesc_index at some point?
		del self.filedesc[fh]

	def statfs(self, path):
		stv = os.statvfs(self.root)
		return dict((key, getattr(stv, key)) for key in ('f_bavail', 'f_bfree',
			'f_blocks', 'f_bsize', 'f_favail', 'f_ffree', 'f_files', 'f_flag',
			'f_frsize', 'f_namemax'))

	def flush(self, path, fh):
		pass

	def readlink(self, path):
		# We never expose any symlink, therefore it should be safe to always
		# return EINVAL:
		raise FuseOSError(errno.EINVAL)

	# Functions that make no sense for a read-only filesystem:

	def utimens(self, path, times=None):
		return self.read_only()

	def mknod(self, path, mode, dev):
		return self.read_only()

	def rmdir(self, path):
		return self.read_only()

	def mkdir(self, path, mode):
		return self.read_only()

	def chmod(self, path, mode):
		return self.read_only()

	def chown(self, path, uid, gid):
		return self.read_only()

	def unlink(self, path):
		return self.read_only()

	def symlink(self, name, target):
		return self.read_only()

	def rename(self, old, new):
		return self.read_only()

	def link(self, target, name):
		return self.read_only()

	def create(self, path, mode, fi=None):
		return self.read_only()

	def write(self, path, buf, offset, fh):
		return self.read_only()

	def truncate(self, path, length, fh=None):
		return self.read_only()

	def fsync(self, path, fdatasync, fh):
		return self.read_only()

def main(conf_path, mountpoint):
	conf = {}
	with open(conf_path) as conf_file:
		conf = yaml.load(conf_file.read())
	FUSE(CombinedFS(conf), mountpoint, nothreads=True, foreground=True, default_permissions=True, allow_other=True)

if __name__ == '__main__':
	main(sys.argv[1], sys.argv[2])
