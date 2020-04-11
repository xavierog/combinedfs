#!/usr/bin/env python3

# Copyright © 2020 Xavier G. <xavier.combinedfs@kindwolf.org>
# This work is free. You can redistribute it and/or modify it under the
# terms of the Do What The Fuck You Want To Public License, Version 2,
# as published by Sam Hocevar. See the COPYING file for more details.

import os
import re
import sys
import stat
import yaml
import errno
import argparse
import threading

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
DEFAULT_UID = 0
DEFAULT_GID = 0
DEFAULT_DIR_MODE = 0o555
DEFAULT_REG_MODE = 0o444
DEFAULT_KEY_MODE = 0o400
DEFAULT_SENSITIVE_PATTERN = '/privkey.pem$'
TIME_PROPS = ('st_atime', 'st_ctime', 'st_mtime')

def read_mode_setting(obj, key, default):
	try:
		return int(obj[key], 8)
	except (KeyError, ValueError):
		return default

class CombinedFSConfiguration(object):
	def __init__(self, conf_path):
		self.read_conf(conf_path)

	def read_conf(self, conf_path):
		with open(conf_path) as conf_file:
			conf = yaml.load(conf_file.read())
			self.apply_conf(conf)
			self.path = conf_path

	def apply_conf(self, conf):
		self.root = conf.get('letsencrypt_live', DEFAULT_ROOT)
		self.filter = conf.get('cert_filter', DEFAULT_CERT_FILTER)
		self.whitelist = conf.get('cert_whitelist', DEFAULT_WHITELIST)
		self.pattern = conf.get('cert_pattern', DEFAULT_CERT_PATTERN)
		self.separator = conf.get('separator', DEFAULT_SEPARATOR)
		self.files = conf.get('files', {})
		self.uid = int(conf.get('uid', DEFAULT_UID))
		self.gid = int(conf.get('gid', DEFAULT_GID))
		self.dir_mode = read_mode_setting(conf, 'dir_mode', DEFAULT_DIR_MODE)
		self.reg_mode = read_mode_setting(conf, 'reg_mode', DEFAULT_REG_MODE)
		self.key_mode = read_mode_setting(conf, 'key_mode', DEFAULT_KEY_MODE)
		self.sensitive_pattern = conf.get('sensitive_pattern', DEFAULT_SENSITIVE_PATTERN)
		# Compile regexes:
		self.sensitive_pattern_re = re.compile(self.sensitive_pattern)
		if self.filter:
			self.pattern_re = re.compile(self.pattern)

	# Helpers:
	def filter_cert(self, cert):
		if not self.filter:
			return True
		return bool(self.pattern_re.match(cert)) == self.whitelist

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

	def expand_path(self, cert, path):
		expanded_path = path.replace('${cert}', cert)
		if not expanded_path.startswith('/'):
			expanded_path = os.path.join(self.root, cert, expanded_path)
		return expanded_path

	def expand_paths(self, cert, paths):
		expanded_paths = []
		for path in paths:
			method = self.expand_paths if type(path) is list else self.expand_path
			expanded_paths.append(method(cert, path))
		return expanded_paths

	def get_paths(self, cert, file_spec):
		return self.expand_paths(cert, file_spec.get('content', []))

	def is_sensitive_file(self, filepath):
		return self.sensitive_pattern_re.search(filepath)

class CombinedFS(Operations):
	def __init__(self, conf_path):
		# Configuration:
		self.configuration = CombinedFSConfiguration(conf_path)
		# File descriptor management:
		self.filedesc_lock = threading.Lock()
		self.filedesc_index = 0
		self.filedesc = {}

	# Helpers:
	def attributes(self, full_path):
		st = os.lstat(full_path)
		return dict((key, getattr(st, key)) for key in ('st_atime', 'st_ctime',
		      'st_gid', 'st_mode', 'st_mtime', 'st_nlink', 'st_size', 'st_uid'))

	def get_conf(self):
		return self.configuration

	def iterate_paths(self, func, paths):
		for filepath in paths:
			try:
				if type(filepath) is list:
					# Array of file paths: look for the first existing path:
					for index, subpath in enumerate(filepath):
						try:
							func(subpath)
							# Still there? The file must exist, exit the loop:
							break
						except OSError as ose:
							if ose.errno == errno.ENOENT and index < len(filepath) - 1:
								# The file does not exist, try the next one, if any:
								continue
							else:
								# Reached the last file path or encountered another error:
								raise
				else:
					# Presumably a regular file path
					func(filepath)
			except OSError as ose:
				raise FuseOSError(ose.errno)

	def register_fd(self, file_descriptor):
		with self.filedesc_lock:
			self.filedesc_index += 1
			new_fd_index = self.filedesc_index
			self.filedesc[new_fd_index] = file_descriptor
		return new_fd_index

	# Filesystem methods

	def access(self, path, mode):
		"""
		libfuse documentation states:
		  This will be called for the access() system call. If the
		  'default_permissions' mount option is given, this method is not called.
		Since this program enforces default_permissions, this method will never
		be called, which makes it dead simple to implement.
		"""
		raise FuseOSError(errno.ENOTSUP)

	def getattr(self, path, fh=None):
		conf = self.get_conf()
		cert, filename, file_spec = conf.analyse_path(path)
		if filename is None: # Directory
			full_path = os.path.join(conf.root, path.lstrip('/'))
			dir_attrs = self.attributes(full_path)
			dir_attrs['st_uid'] = conf.uid
			dir_attrs['st_gid'] = conf.gid
			dir_attrs['st_mode'] = stat.S_IFDIR | conf.dir_mode
			return dir_attrs
		attrs = {
			'st_nlink': 1,
			'st_uid': file_spec.get('uid', conf.uid),
			'st_gid': file_spec.get('gid', conf.gid),
			'st_size': 0,
		}
		def_mode = conf.reg_mode
		paths = conf.get_paths(cert, file_spec)
		if not paths:
			# Virtual empty file:
			root_stats = os.stat(conf.root)
			for prop in TIME_PROPS:
				attrs[prop] = getattr(root_stats, prop)
			attrs['st_mode'] = stat.S_IFREG | read_mode_setting(file_spec, 'mode', def_mode)
			return attrs
		# One array to hold the actual, successive filepaths, one dict to hold
		# the latest stat() result for each file:
		filepaths = []
		stats = {}
		def stat_file(path):
			stats[path] = os.stat(path)
			filepaths.append(path)
		self.iterate_paths(stat_file, paths)
		for filepath in filepaths:
			stat_obj = stats[filepath]
			# Pick the highest/latest value for access/change/modification times:
			for prop in TIME_PROPS:
				prop_val = getattr(stat_obj, prop)
				if prop_val > attrs.get(prop, 0):
					attrs[prop] = prop_val
			# Add up sizes:
			attrs['st_size'] += stat_obj.st_size
			# Lower permissions if necessary:
			if conf.is_sensitive_file(filepath):
				def_mode = conf.key_mode
		attrs['st_mode'] = stat.S_IFREG | read_mode_setting(file_spec, 'mode', def_mode)
		return attrs

	def readdir(self, path, fh):
		conf = self.get_conf()
		cert, filename, _ = conf.analyse_path(path)
		# Deal only with directories:
		if filename:
			raise FuseOSError(errno.ENOTDIR)
		# Extra attributes, just what it takes to support dirent->d_type:
		dir_attrs = {'st_mode': stat.S_IFDIR }
		reg_attrs = {'st_mode': stat.S_IFREG }
		# Yield common directory entries:
		yield '.', dir_attrs, 0
		yield '..', dir_attrs, 0
		if not cert:
			# Top-level directory
			flat_mode = conf.separator != '/'
			for cert in (d for d in os.listdir(conf.root) if conf.filter_cert(d)):
				if flat_mode:
					for filename in conf.files:
						yield cert + conf.separator + filename, reg_attrs, 0
				else:
					yield cert, dir_attrs, 0
		else:
			# Second-level directory
			for filename in conf.files:
				yield filename, reg_attrs, 0

	def open(self, path, flags):
		conf = self.get_conf()
		cert, filename, file_spec = conf.analyse_path(path)
		if not cert or not filename:
			raise FuseOSError(errno.ENOENT)
		# Being a read-only filesystem spares us the need to check most flags.
		new_fd = {
			'conf': conf,
			'cert': cert,
			'filename': filename,
			'file_spec': file_spec,
		}
		return self.register_fd(new_fd)

	def read(self, path, length, offset, fh):
		filedesc = self.filedesc.get(fh)
		# Use the same configuration as open() when it created the file descriptor:
		conf = filedesc['conf']
		if filedesc is None:
			raise FuseOSError(errno.EBADF)
		data = filedesc.get('data')
		if data is None:
			paths = conf.get_paths(filedesc['cert'], filedesc['file_spec'])
			data = {'data': bytes() }
			def concatenate(path):
				data['data'] += open(path, 'rb').read()
			self.iterate_paths(concatenate, paths)
			filedesc['data'] = data = data['data']
		read_chunk = data[offset:offset + length]
		return read_chunk

	def release(self, path, fh):
		with self.filedesc_lock:
			del self.filedesc[fh]
		# Integers in Python have arbitrary precision, i.e. they are unbounded
		# and thus exempt from overflows as long as they are manipulated in
		# pure Python.

	def statfs(self, path):
		stv = os.statvfs(self.get_conf().root)
		return dict((key, getattr(stv, key)) for key in ('f_bavail', 'f_bfree',
			'f_blocks', 'f_bsize', 'f_favail', 'f_ffree', 'f_files', 'f_flag',
			'f_frsize', 'f_namemax'))

	def readlink(self, path):
		# We never expose any symlink, therefore it should be safe to always
		# return EINVAL:
		raise FuseOSError(errno.EINVAL)

def main(conf_path, mountpoint, foreground):
	FUSE(CombinedFS(conf_path), mountpoint, foreground=foreground, ro=True, default_permissions=True, allow_other=True)

if __name__ == '__main__':
	parser = argparse.ArgumentParser(description='Expose a transformed, version of Let\'s Encrypt / Certbot\'s "live" directory')
	parser.add_argument('conf_path', help='CombinedFS configuration file')
	parser.add_argument('mountpoint', help='mount point')
	parser.add_argument('-o', dest='options', help='mount options (ignored, only there for compatibility purposes)')
	parser.add_argument('-f', '--foreground', dest='foreground', help='run in the foreground', action='store_true')
	args = parser.parse_args()
	main(args.conf_path, args.mountpoint, args.foreground)
