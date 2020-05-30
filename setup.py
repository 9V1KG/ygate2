from setuptools import setup

requirements = "pyserial", "requests", "pylint"
setup(
    name="ygate2",
    version="2.0a0",
    packages=["ygate2", "aprsutils", "kiss"],
    url="https://github.com/9V1KG/ygate2",
    license="Please check with author",
    author="9V1KG",
    author_email="drklaus@bpmsg.com",
    install_requires=requirements,
    extras_require={
        'dev': [
            'pylint'
            'pytest',
            'pytest-pep8',
            'pytest-cov',
            'sphinx',
            'recommonmark',
            'black',
            'pylint'
        ]},
    description="IGate V2.0 for Yaesu radio",
)