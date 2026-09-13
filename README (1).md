# GF(256) AES: Mathematical Foundations and Python Implementation

This repository accompanies a mathematical report on AES and finite-field
arithmetic. It combines:

1. the construction of $\mathrm{GF}(256)$;
2. polynomial arithmetic over $\mathrm{GF}(2)$;
3. multiplicative inversion via the extended Euclidean algorithm;
4. generation of the standard AES S-box;
5. AES-128 key expansion and round transformations;
6. PKCS#7 padding;
7. AES encryption/decryption in ECB mode; and
8. a mathematical proposal for additional master-key preprocessing using
   trace, norm, a permutation polynomial, and a linear transformation.

## Repository structure

```text
GF256-AES/
├── main.tex
├── README.md
├── LICENSE
├── .gitignore
├── run_example.py
├── src/
│   ├── __init__.py
│   └── aes.py
├── figures/
└── .github/
    └── workflows/
        └── latex.yml
```

## Mathematical model

The field used by AES is represented as

$$
\mathrm{GF}(256)
=
\mathrm{GF}(2)[x]/(x^8+x^4+x^3+x+1).
$$

For the exploratory key-preprocessing construction, two bytes are regarded
as an element

$$
\beta=a+b\theta
$$

of $\mathrm{GF}(2^{16})$, where the extension is described by

$$
\theta^2+\theta=33.
$$

The report derives

$$
\operatorname{Tr}_{\mathrm{GF}(2^{16})/\mathrm{GF}(2^8)}(\beta)=b
$$

and

$$
N_{\mathrm{GF}(2^{16})/\mathrm{GF}(2^8)}(\beta)
=a^2+ab+33b^2.
$$

The proposed nonlinear preprocessing is

$$
v_i=u_i^7+t_i u_i+n_i+C_i,
$$

followed by a full-rank linear transformation

$$
V\mapsto MV.
$$

**Important:** this preprocessing is an experimental mathematical proposal,
not part of the standard AES specification. The Python implementation in
`src/aes.py` implements the AES procedure represented by the original code;
the proposed trace/norm preprocessing is documented in `main.tex` but is not
silently inserted into standard AES.

## Run the Python example

From the repository root:

```bash
python run_example.py
```

The example uses the original project's key and plaintext:

```text
key       = 00 01 ... 0f
plaintext = "mathematical science"
```

It checks that encryption followed by decryption recovers the original
plaintext after PKCS#7 unpadding.

## LaTeX / Overleaf

`main.tex` is a standalone LaTeX document. Upload the repository to Overleaf
or upload `main.tex` directly.

The GitHub Actions workflow automatically compiles the paper whenever changes
are pushed to `main`.

## Security note

The implementation is intended for mathematical study and educational use.
ECB mode is not recommended for real-world data because identical plaintext
blocks produce identical ciphertext blocks. For production cryptography,
use a vetted cryptographic library and an authenticated encryption mode.

## AI assistance disclosure

AI assistance was used for some implementation details, including polynomial
division, multiplicative inversion, and linear transformations, and for
identifying implementation issues. The mathematical report contains the
corresponding disclosure.
