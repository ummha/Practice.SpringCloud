package com.msa.sample;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.cloud.client.discovery.EnableDiscoveryClient;

@EnableDiscoveryClient
@SpringBootApplication
public class SampleApiApplication {
    public static void main(String[] args) {
        SpringApplication.run(SampleApiApplication.class, args);
    }
}
