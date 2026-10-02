from setuptools import setup, find_packages
import os

# le a versao do pacote sem importar
ver = {}
with open(os.path.join(os.path.dirname(__file__), "biluzim", "__init__.py"), encoding="utf-8") as fh:
    for line in fh:
        if line.startswith("__version__"):
            exec(line, ver)

setup(
    name="biluzim",
    version=ver["__version__"],
    description="Reconhecimento passivo + enumeracao ativa em uma ferramenta so (juncao de lunatic + koffuster)",
    long_description="Biluzim: recon passivo de subdominios via fontes OSINT (lunatic) "
                     "e enumeracao ativa dir/dns/vhost/fuzz/s3/gcs/tftp (koffuster), "
                     "com ponte passivo->ativo. Uso autorizado apenas.",
    author="lunalully (porte Python)",
    license="GPL-3.0-or-later",
    packages=find_packages(exclude=("labs",)),
    include_package_data=True,
    package_data={"biluzim": ["wordlists/*.txt"]},
    python_requires=">=3.9",
    entry_points={"console_scripts": ["biluzim=biluzim.cli:main"]},
    classifiers=[
        "Environment :: Console",
        "Programming Language :: Python :: 3",
        "Topic :: Security",
    ],
)
