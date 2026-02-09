spring.application.name=AuthAdminStarter

# Nombre de la base de datos y consola
spring.datasource.url=jdbc:h2:mem:AuthAdminStarterdb
# Solo desarrollo
spring.h2.console.enabled=true
spring.h2.console.path=/h2-console

# Para que Hibernate cree las tablas automáticamente al empezar
spring.jpa.hibernate.ddl-auto=update
spring.jpa.show-sql=true
#solo en desarrollo
# Muestra qué está pasando con la seguridad
logging.level.org.springframework.security=DEBUG
# Muestra las consultas SQL que se hacen a la base de datos
logging.level.org.hibernate.SQL=DEBUG
# Muestra los valores que se guardan o buscan en las tablas
logging.level.org.hibernate.type.descriptor.sql.BasicBinder=TRACE

app.admin.email=admin@admin.com
app.admin.password=admin1234
app.admin.username=admin

app.mailjet.senderemail = example@example.com
app.mailjet.apikey = yourapikey
app.mailjet.secretapikey = yoursecretapikey