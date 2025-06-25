def show_permissions(console, manager):
    console.print(f"Allowed paths: {list(manager.allowed_paths)}")
