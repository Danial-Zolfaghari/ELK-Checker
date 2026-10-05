import os
from elkcheck import create_app

app = create_app()


if __name__ == "__main__":
    app.run(host=os.getenv("ELK_HOST", "127.0.0.1"), port=int(os.getenv("ELK_PORT", "14061")), debug=False)
