from fastapi import FastAPI

app = FastAPI(title="ContainerGuard")


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "broken"}
