from setuptools import setup
from distutils.extension import Extension
from Cython.Build import cythonize

extensions = [
    Extension(
        name="pydbg.impl", 
        sources=[
            "src/impl/__impl.pyx",
            "src/impl/winhelper.c"
        ], 
        libraries=["user32"],
        include_dirs=["src/impl"]
    )
]

setup(
    name='pydbg',
    packages=['pydbg'],
    package_dir={'pydbg':'src'},
    ext_modules = cythonize(
        module_list=extensions,
        build_dir="build",
        compiler_directives = {
            'language_level' : "3"
        }
    )
)