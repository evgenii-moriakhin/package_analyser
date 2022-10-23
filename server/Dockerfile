FROM python:3

WORKDIR /usr/src/server_analyser

COPY requirements.txt ./
RUN apt-get install libpq-dev
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

CMD [ "python", "app.py" ]
