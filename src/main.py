import uvicorn
from fastapi import FastAPI

from onetimesecrets.routers import generate_secret_router, get_secret_router

app = FastAPI(
    title="Onetimesecrets"
)


app.include_router(
    generate_secret_router,
    prefix="/generate")

app.include_router(
    get_secret_router,
)

if __name__ == "__main__":
    uvicorn.run("main:app",host="0.0.0.0", port=8000, reload=True)









