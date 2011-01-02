from distutils.core import setup, Extension

module = Extension('data',
                   sources=['pymodule.c'],
                   library_dirs = ['.'],
                   libraries = ['data'],
                   cflags = ['-std=gnu99'])

setup(name = 'data',
      version = '0.0',
      description = '',
      ext_modules = [module])
