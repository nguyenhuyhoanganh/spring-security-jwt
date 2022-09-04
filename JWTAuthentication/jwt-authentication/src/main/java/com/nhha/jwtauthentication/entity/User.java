package com.nhha.jwtauthentication.entity;

import java.io.Serializable;
import java.util.Date;
import java.util.Set;

import javax.persistence.CollectionTable;
import javax.persistence.Column;
import javax.persistence.ElementCollection;
import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import javax.persistence.JoinColumn;
import javax.persistence.Table;

import lombok.Data;

@Entity
@Table(name = "user")
@Data
public class User implements Serializable{
	
	private static final long serialVersionUID = 1L;

	@Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
	@Column(nullable = false, updatable = false)
	private Long id;
	
	@Column(name = "user-id", nullable = false, updatable = false)
	private String userId;
	
	private String firstName;
	
	private String lastName;
	
	@Column(name = "username", nullable = false, updatable = false)
	private String username;
	
	@Column(name = "password", nullable = false)
	private String password;
	
	private String email;
	
	private String profileImageUrl;
	
	private Date lastLoginDate;
	
	private Date lastLoginDateDisplay;
	
	private Date joinDate;
	
	@ElementCollection
    @CollectionTable(name = "user_role", joinColumns = @JoinColumn(name = "account_id"))
    @Column(name = "role")
	private Set<String> roles; //ROLE_USER, ROLE_ADMIN
	
	@ElementCollection
    @CollectionTable(name = "user_authority", joinColumns = @JoinColumn(name = "account_id"))
    @Column(name = "authority")
	private Set<String> authorities; //read, write
	
	private boolean isActive;
	
	private boolean isNotLocked;
	
}
