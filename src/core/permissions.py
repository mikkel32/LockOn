class PermissionManager:
    def __init__(self):
        self.allowed_paths = set()

    def allow(self, path: str):
        self.allowed_paths.add(path)

    def is_allowed(self, path: str) -> bool:
        return path in self.allowed_paths
