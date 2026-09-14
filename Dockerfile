FROM python:3.12-slim
LABEL org.opencontainers.image.source=https://github.com/metrafonic/openhop-rxcompare
WORKDIR /app
COPY rxcompare.py server.py ./
ENV PYTHONUNBUFFERED=1 PORT=8080
EXPOSE 8080
RUN useradd -r -u 10001 app
USER app
HEALTHCHECK --interval=60s --timeout=5s --start-period=90s \
  CMD python3 -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8080/healthz').status==200 else 1)"
CMD ["python3", "server.py"]
