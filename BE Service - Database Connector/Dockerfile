# syntax=docker/dockerfile:1.3
# escape=`

FROM domrec-databaseconnector:latest

LABEL Author="Or Ben Shimon"`
    Corp="BenShimonTechnologiesLLC"`
    Project="DomRec"`
    Version="3"`
    Minor="Alpha 1.0"

ENV DBCredentials_File = ./Configuration/DBCredentials.json

WORKDIR /opt
COPY . .

CMD ["python", "./MainCode/Main.py"]
EXPOSE 5090