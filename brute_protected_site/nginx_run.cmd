docker stop nginx-brute
docker build -t nginx-brute ./nginx
docker run --name nginx-brute --rm --mount type=bind,src="C:\UniversitySpace\Латыпов\Практика 3\Сервант\site",dst=/var/www/html/ -d -p 8080:80 --network brute-network-external nginx-brute
