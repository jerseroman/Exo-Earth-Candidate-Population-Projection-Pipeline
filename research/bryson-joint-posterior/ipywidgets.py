"""Non-interactive compatibility stub for the public Bryson model module.

``rateModels3D.py`` imports ``FloatProgress`` for notebook plotting utilities,
but the posterior runner never instantiates it.  Keeping this local no-op stub
avoids adding Jupyter as a scientific runtime dependency.
"""


class FloatProgress:
    def __init__(self, *args, **kwargs):
        self.value = kwargs.get("value", 0)
