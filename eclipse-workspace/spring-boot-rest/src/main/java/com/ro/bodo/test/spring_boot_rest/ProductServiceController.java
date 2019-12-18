package com.ro.bodo.test.spring_boot_rest;

import java.util.HashMap;
import java.util.Map;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class ProductServiceController {
	private static Map<String, Product> productRepo = new HashMap<>();
	
	static {
		Product honey = new Product();
		honey.setId("1");
		honey.setName("Honey");
		productRepo.put(honey.getId(), honey);
		
		Product almond = new Product();
		almond.setId("2");
		almond.setName("Almond");
		productRepo.put(almond.getId(), almond);
	}
	
	@RequestMapping(value = "/products", method = RequestMethod.GET)
	public ResponseEntity<Object> getProducts() {
		return new ResponseEntity<Object>(productRepo.values(), HttpStatus.OK);
	}
	
	@RequestMapping(value = "/products", method = RequestMethod.POST)
	public ResponseEntity<Object> createProduct(@RequestBody Product product) {
		productRepo.put(product.getId(), product);
		return new ResponseEntity<>("Product is created successfully", HttpStatus.CREATED);
	}
	
	@RequestMapping(value = "/products/{id}", method = RequestMethod.PUT)
	public ResponseEntity<Object> updateProduct(@PathVariable("id") String id, @RequestBody Product product) {
		productRepo.remove(id);
	    product.setId(id);
	    productRepo.put(id, product);
		return new ResponseEntity<>("Product is updated successfully", HttpStatus.OK);
	}
	
	@RequestMapping(value = "/products/{id}", method = RequestMethod.DELETE)
	public ResponseEntity<Object> delete(@PathVariable("id") String id) { 
	    productRepo.remove(id);
	    return new ResponseEntity<>("Product is deleted successsfully", HttpStatus.OK);
	}
	
	@RequestMapping(value = "/products/{id}", method = RequestMethod.GET)
	   public ResponseEntity<Object> getProductById(@PathVariable("id") String id) {   
	      return new ResponseEntity<>(productRepo.get(id), HttpStatus.OK);
	}
	
	@RequestMapping(value = "/products/foo")
	public ResponseEntity<Object> getProduct(
		@RequestParam(value = "name", required = false, defaultValue = "Honey")	String name) {
		for(Product i : productRepo.values()) {
			if(i.getName().equals(name)) {
				return new ResponseEntity<>(i, HttpStatus.OK);
			}
		}
		
		return new ResponseEntity<>("Product not found by name", HttpStatus.BAD_REQUEST);
	}
	
}
