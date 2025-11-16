from setuptools import setup
from setuptools.dist import Distribution
from wheel.bdist_wheel import bdist_wheel as _bdist_wheel


class BinaryDistribution(Distribution):
    def has_ext_modules(self):
        return True


class bdist_wheel(_bdist_wheel):
    def finalize_options(self):
        super().finalize_options()
        self.root_is_pure = False


    def get_tag(self):
        _, _, plat = super().get_tag()
        return ('py3', 'none', plat)


setup(
    name="parascope",
    version="0.3.0",
    packages=["parascope"],
    distclass=BinaryDistribution,
    cmdclass={"bdist_wheel": bdist_wheel},
)
