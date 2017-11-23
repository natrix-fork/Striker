FROM ubuntu:latest
MAINTAINER Cheban Alexei 'al.chebn@gmail.com'
RUN apt-get update -y
RUN apt-get install -y python-pip python-dev build-essential git
RUN git clone https://github.com/Cheban1996/Striker.git
WORKDIR /Striker 
RUN pip install -r requirements.txt
ENTRYPOINT ["python", "striker.py"]
CMD [""]
