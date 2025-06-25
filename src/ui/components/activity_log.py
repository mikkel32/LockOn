def show_logs(console, log_file):
    with open(log_file) as f:
        console.print(f.read())
