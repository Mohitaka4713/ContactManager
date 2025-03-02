package com.smart.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;

import com.smart.dao.UserRepository;
import com.smart.entities.Contact;
import com.smart.entities.User;
import com.smart.helper.Message;



import jakarta.servlet.http.HttpSession;
import jakarta.validation.Valid;

@Controller

public class HomeController {

@Autowired
private BCryptPasswordEncoder passwordEncoder;
	
	
	@Autowired
	private UserRepository userRepository;
	

	 
		@GetMapping("/test")
		@ResponseBody
		public String test() {
			
			User user = new User();
			user.setName("Mohit Chaurasia");
			user.setEmail("mohit@123gmail.com");
			
			Contact contact = new Contact();
			user.getContacts().add(contact);
		
			userRepository.save(user);
			System.out.println("User" +user);
			return "Working";
			
		}
		 
		@RequestMapping("/")
	//	@GetMapping("/home")
		public String home(Model model) {
			
			model.addAttribute("title", "Home - Smart Contact Manager");
			return "home";
			
		}
		
		@RequestMapping("/about")
	//	@GetMapping("/home")
		public String about(Model model) {
			
			model.addAttribute("title", "About - Smart Contact Manager");
			return "about";
			
		}
		
		@RequestMapping("/signup/")
		//	@GetMapping("/home")
			public String signup(Model model) {
				
				model.addAttribute("title", "Signup - Smart Contact Manager");
				model.addAttribute("user", new User());
				return "signup";
				
			}
	
		
	
		
		//handler for registering user
		@RequestMapping(value = "/do_register", method = RequestMethod.POST)
		public String registerUser(@Valid @ModelAttribute("user") User user, BindingResult result1, @RequestParam(value = "agreement", defaultValue= "false")boolean agreement, Model model, HttpSession session) {
			
		try {
			if(!agreement) {
				System.out.print("You have not agreed the terms and conditions");
				throw new Exception("You have not agreed the terms and conditions");
			}if(result1.hasErrors()) {
				System.out.println("Error: " +result1.toString());
				model.addAttribute("user", user);
				return "signup";
			}
			
		
			
			user.setRole("ROLE_USER"); 
			user.setEnabled(true);
			user.setImageUrl("default.png");
	 		user.setPassword(passwordEncoder.encode(user.getPassword()));
			
			
			
			System.out.print("Agreement = " +agreement);
			System.out.print("User = " +user);
			
			User result = this.userRepository.save(user);
			
			model.addAttribute("user", result);
			session.setAttribute("message", new Message("Successfully Registered", "alert-success"));
			return "signup";
		}
		catch(Exception e){
			
			e.printStackTrace();
			session.setAttribute("message", new Message("Something Went Wrong!"+e.getMessage(), "alert-danger"));
			return "signup";
		}
			
		}
		//handler for custom login
		@GetMapping("/signin")
		public String customLogin(Model model) {
			model.addAttribute("title", "Login Page");
			return "login";
		}
		
		
 
}