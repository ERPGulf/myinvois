import warnings

msg = """
`frappe` package is installed from PyPI, which isn't supported. Please install frappe using frappe bench or docker images.

- https://github.com/frappe/bench
- https://github.com/frappe/frappe_docker
"""

warnings.warn(
	msg,
	category=UserWarning,
	stacklevel=2,
)
