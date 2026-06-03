from setuptools import setup, find_packages

with open('README.md') as f:
    readme = f.read()

with open('LICENSE') as f:
    license = f.read()

with open('requirements.txt') as f:
    requirements = f.read().splitlines()

setup(
    name='cmloot',
    scripts=['cmloot.py', 'cmloot_analyze.py'],
    version='2.0.0',
    long_description=readme,
    long_description_content_type='text/markdown',
    author='Andreas Vikerup (Shelltrail), contributors',
    url='https://github.com/shelltrail/cmloot',
    license='MIT',
    install_requires=requirements
)
