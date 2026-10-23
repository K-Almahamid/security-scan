from fastapi import FastAPI

app = FastAPI()


@app.get("/run")
def run(cmd: str):
    return eval(cmd)
