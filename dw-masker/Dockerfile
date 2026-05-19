FROM python:3.12-slim
WORKDIR /app
COPY dw-masker/requirements.txt .
RUN pip install --no-cache-dir --trusted-host pypi.org --trusted-host files.pythonhosted.org -r requirements.txt
COPY masking_sdk /app/masking_sdk
COPY dw-masker/app.py .
CMD ["python", "app.py"]
