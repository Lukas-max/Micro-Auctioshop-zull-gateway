package luke.auctioshopzullgateway;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.cloud.netflix.eureka.EnableEurekaClient;

@SpringBootApplication
@EnableEurekaClient
public class AuctioshopZullGatewayApplication {

    public static void main(String[] args) {
        SpringApplication.run(AuctioshopZullGatewayApplication.class, args);
    }

}
