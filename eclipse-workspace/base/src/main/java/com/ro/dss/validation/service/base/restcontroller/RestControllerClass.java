package com.ro.dss.validation.service.base.restcontroller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;


@RestController
public class RestControllerClass {

	@RequestMapping(value = "/")
	public String hello() {
		return "Main RestControllerClass";
	}
}
