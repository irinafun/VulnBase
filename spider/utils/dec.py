class Singleton(type):
    """
    单例模式
    """
    _instances = {}

    def __call__(cls, *args, **kwargs):
        if cls not in cls._instances:
            # cls._instances[cls] = super(Singleton, cls).__call__(*args, **kwargs)
            cls._instances[cls] = super().__call__(*args, **kwargs)
        return cls._instances[cls]