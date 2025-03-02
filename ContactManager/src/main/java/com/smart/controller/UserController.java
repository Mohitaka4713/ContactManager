package com.smart.controller;

import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.security.Principal;
import java.util.Optional;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.io.ClassPathResource;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.multipart.MultipartFile;

import com.smart.dao.ContactRepository;
import com.smart.dao.UserRepository;
import com.smart.entities.Contact;
import com.smart.entities.User;
import com.smart.helper.Message;

import jakarta.servlet.http.HttpSession;

import org.springframework.ui.Model;




@Controller
 @RequestMapping("/user")
public class UserController {
	
	
	@Autowired
	private UserRepository userRepository;
	
	@Autowired
	private ContactRepository contactRepository;
	
	
	//method for adding common data response
	@ModelAttribute
	public void addCommonData(Model model, Principal principal) {
		
		String userName = principal.getName();
		System.out.println("USER NAME : "+userName);
		
		//get the user using username(Email)
		
		User user = userRepository.getUserByUserName(userName);
		
	System.out.println("USER : "+user);
	
	model.addAttribute("user", user);
	
	}

//dashboard home	
	@RequestMapping("/index")
	public String dashboard(Model model, Principal principal) {
		model.addAttribute("Title", "User Dashboard");
		return "normal/user_dashboard";
	}
	
	
	//open add form handler
	@GetMapping("/add-contact")
	public String openAddContactForm(Model model) {
		model.addAttribute("Title", "Add Contact");
		model.addAttribute("contact", new Contact());
		return "normal/add_contact_form";
	}
	
	//processing add contact form
	@PostMapping("/process-contact")
	public String processContact(
			@ModelAttribute Contact contact, //When data inside the form matches comes in this field
			@RequestParam("profileImage") MultipartFile file, //image coming in this field
			Principal principal, // Fetching user details
			HttpSession session)
	{
		
		
		try {
		String name = principal.getName();
		User user=this.userRepository.getUserByUserName(name);
		
		//Processing and uploading files......
		
		if(file.isEmpty()) {
			
			//if file is empty
			
			System.out.println("Image is empty");
			contact.setImage("contact.png");
			
		}else {
			//upload the file to folder and update the name to contact
			
			contact.setImage(file.getOriginalFilename());
			File saveFile=new ClassPathResource("static/img").getFile();
			
			Path path= Paths.get(saveFile.getAbsolutePath()+File.separator+file.getOriginalFilename());
			
			Files.copy(file.getInputStream(), path, StandardCopyOption.REPLACE_EXISTING);
			
			System.out.println("Image is uploaded");
		}
		
		
		
		
		user.getContacts().add(contact);
		contact.setUser(user);
		
		this.userRepository.save(user);
		System.out.println("Contact : " +contact);
		
		//Message Success
		
		session.setAttribute("message", new Message("Your Contact is Added", "success"));
		
		
		}catch(Exception e) {
			System.out.println("Error : "+e.getMessage());
			e.printStackTrace();		
			
			
			//error message 
			
			session.setAttribute("message", new Message("Something Went Wrong !! Try Again......", "danger"));
			
			
			
		}
		
		
		return "normal/add_contact_form";
	}
	
	
	//show contacts handler
	//per page = 10[n]
	//current page = 0[page]
	
	
	@GetMapping("/show-contacts/{page}")
	public String showContacts(@PathVariable("page") Integer page,Model m, Principal principal) {
		m.addAttribute("title", "Show User Contacts");
		
		//contact ki list bhejne ke liye
		
		String userName= principal.getName();
		User user =this.userRepository.getUserByUserName(userName);
		
		Pageable pageable = PageRequest.of(page, 7);
	Page<Contact> contacts = this.contactRepository.findContactsByUser(user.getId(),pageable);

		m.addAttribute("contacts", contacts);
		m.addAttribute("currentPage", page);
		m.addAttribute("totalPages", contacts.getTotalPages());
		
	 
		
		return "normal/show_contacts";
	}
	
	//showing particular contact details.
	
	@RequestMapping("/{cId}/contact")
	public String showContactDetail(@PathVariable("cId") Integer cId, Model model, Principal principal) {
		
		System.out.println("CID :" +cId);
	
		  Optional<Contact> contactOptional=this.contactRepository.findById(cId);
		  Contact contact=contactOptional.get();
		  
		  String userName=principal.getName();
		  User user= this.userRepository.getUserByUserName(userName);
		  
		  if(user.getId()==contact.getUser().getId()) {
		  model.addAttribute("contact", contact); 
		  model.addAttribute("title", contact.getName());
		  
		  }
		  System.out.println("contact :"+contact);

		return "normal/contact_detail";
	}
	
	//delete contact handler
	
	@GetMapping("/delete/{cid}")
	public String deleteContact(@PathVariable("cid")Integer cId, Model model, HttpSession session, Principal principal) {
		
		
		
 		
		Contact contact =this.contactRepository.findById(cId).get();
		
	//	contact.setUser(null);
		
	//	this.contactRepository.delete(contact);
		
		User user=this.userRepository.getUserByUserName(principal.getName());
		user.getContacts().remove(contact);
		
		this.userRepository.save(user);
		
		System.out.println("DELETED");
		session.setAttribute("message", new Message ("Contact deleted successfully", "success"));
		
		return "redirect:/user/show-contacts/0";
		
	}
	
	//open update from handler
	
	@PostMapping("/update-contact/{cid}")
	public String updateForm(@PathVariable("cid")Integer cid,Model m) {
		
		m.addAttribute("title", "Update Contact");
		
		Contact contact=this.contactRepository.findById(cid).get();
		m.addAttribute("contact", contact);
		
		return "normal/update-form";
		
		
	}
	
	
	//Update contact handler
	
	@RequestMapping(value="/process-update", method=RequestMethod.POST)
	public String updateHandler(@ModelAttribute Contact contact, @RequestParam("profileImage")MultipartFile file, Model m, HttpSession session, 
			Principal principal) {
		
		try {
			
			// Fetching old contact details
			
			Contact oldcontactDetail=this.contactRepository.findById(contact.getcId()).get();			
			
			//image
			if(!file.isEmpty()) {
				//file work...
				
				
				//rewrite
				
				//delete old photo
				
				File deleteFile=new ClassPathResource("static/img").getFile();
				
				File file1=new File(deleteFile, oldcontactDetail.getImage());
				file1.delete();				
				
				
				
				// update new photo
				
				File saveFile=new ClassPathResource("static/img").getFile();
				
				Path path= Paths.get(saveFile.getAbsolutePath()+File.separator+file.getOriginalFilename());
				
				Files.copy(file.getInputStream(), path, StandardCopyOption.REPLACE_EXISTING);
				
				contact.setImage(file.getOriginalFilename());
				
				
			}else {
				
				contact.setImage(oldcontactDetail.getImage());
			}
			
			User user= this.userRepository.getUserByUserName(principal.getName());
			
			contact.setUser(user);
			this.contactRepository.save(contact);
			
			session.setAttribute("message", new Message("Your Contact is Updated", "success"));
			
		}
		
		catch(Exception e) {
			e.printStackTrace();		}
		
		
		return "redirect:/user/"+contact.getcId()+"/contact";
		
	}
	
	//Your profile handler
	
	@GetMapping("/profile")
	public String yourProfile(Model model) {
		model.addAttribute("title", "Profile Page");
		return "normal/profile";
	}
	
 
}
