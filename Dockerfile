FROM python:3.10-slim

WORKDIR /app

RUN pip install flask flask-cors requests urllib3

COPY . .

ENV PORT=7860
EXPOSE 7860

CMD ["python", "app.py"]