# Generated by Selenium IDE
# -*- coding: utf-8 -*-
#python 3
import pytest
import time
import json
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.common.action_chains import ActionChains
from selenium.webdriver.support import expected_conditions
from selenium.webdriver.support.wait import WebDriverWait
from selenium.webdriver.common.keys import Keys
import os
import sys
cwd = os.path.abspath(os.path.dirname(sys.argv[0]))

#driver_path = cwd + r"\driver\chromedriver.exe"
driver_path = cwd + r"/driver/chromedriver"
checking_tab = False

class Testcase():
  def setup_method(self, option):
    #self.driver = webdriver.Chrome(executable_path=driver_path, options=option)
    self.driver = webdriver.Chrome(options=option)
    self.driver.delete_all_cookies()
    self.vars = {}
  def teardown_method(self, method):
    # self.driver.delete_all_cookies
    self.driver.quit()
    # self.driver.close()
  
  def facebook(self):
    self.driver.set_page_load_timeout(25)
    try:
      #Facebook
      print("[*] Facebook (Social network)")     
      self.driver.get("https://www.facebook.com/")
      self.driver.find_element(By.ID, "email").send_keys("")      #username
      self.driver.find_element(By.ID, "pass").send_keys("")      #password
      self.driver.find_element(By.ID, "pass").send_keys(Keys.ENTER)
      time.sleep(3)
      self.driver.delete_all_cookies()

    except Exception as E:
      self.driver.delete_all_cookies()
      # self.teardown_method('GET')
      print(E)
      pass
      
  def google(self):   
    self.driver.set_page_load_timeout(25)
    try:
      print("[*] Google (Search Engine)")
      self.driver.execute_script("window.open('https://www.google.com')")
      self.driver.switch_to.window(self.driver.window_handles[1])
      self.driver.find_element(By.NAME, "q").send_keys("chrome extension testing")  #search keyword
      self.driver.find_element(By.NAME, "q").send_keys(Keys.ENTER)
      time.sleep(2)
    except Exception as E:
      # self.driver.delete_all_cookies()
      # self.teardown_method('GET')
      print(E)
      pass
    
  def timo(self): 
    self.driver.set_page_load_timeout(25)  
    try:
      #Bank
      print("[*] Timo (Bank)")
      # self.driver.execute_script("window.open('https://www.timo.vn')")
      # self.driver.switch_to_window(self.driver.window_handles[2])
      self.driver.get("https://www.timo.vn/")
      time.sleep(2)
      #self.driver.find_element(By.XPATH, "//li[10]/ul/li/a/span[2]").click()
      self.driver.find_element(By.XPATH, "//li[10]/ul/li/a/span[2]")
      time.sleep(2)
      self.driver.find_element(By.ID, "usernameTxt").send_keys("") #username
      self.driver.find_element(By.ID, "pwRealTxt").send_keys("") #password
      self.driver.find_element(By.ID, "pwRealTxt").send_keys(Keys.ENTER)
      time.sleep(4)
    except Exception as E:
      self.driver.delete_all_cookies()
      # self.teardown_method('GET')
      print(E)
      pass
  def extension_tab(self):
    self.driver.set_page_load_timeout(25)
    try:
      #Chrome ext tab
      print("[*] Chrome Tab (System Tab)")
      time.sleep(2)
      self.driver.get('chrome://extensions')
      time.sleep(2)
    except Exception as E:
      global checking_tab
      checking_tab = True
      pass
      
  def paypal(self):
    self.driver.set_page_load_timeout(25)
    try:
      #Paypal
      print("[*] Paypal (Payments System)")
      global checking_tab
      if(checking_tab == True):
        self.driver.switch_to_window(self.driver.window_handles[0])
        #self.driver.execute_script("window.open('https://www.paypal.com/vn/home')")
        self.driver.get("https://www.paypal.com")
        #self.driver.switch_to_window(self.driver.window_handles[1])
      else:
        #self.driver.execute_script("window.open('https://www.paypal.com/vn/home')")
        #self.driver.switch_to_window(self.driver.window_handles[2])
        self.driver.get("https://www.paypal.com")
        
      # self.driver.get("https://www.paypal.com/vn/home")
      self.driver.find_element(By.ID, "ul-btn").click()
      self.driver.find_element(By.ID, "email").send_keys("")   #username
      self.driver.find_element(By.ID, "email").send_keys(Keys.RETURN)
      time.sleep(1)
      self.driver.find_element(By.ID, "password").send_keys("")    #password
      self.driver.find_element(By.ID, "password").send_keys(Keys.RETURN)
      self.driver.find_element(By.ID, "notNowLink").click()
    except Exception as E:
      self.driver.delete_all_cookies()
      # self.teardown_method('GET')
      print(E)
      

  def amazon(self):
    self.driver.set_page_load_timeout(25)
    try:
      #Amazon
      print("[*] Amazon (E-commerce)")
      self.driver.get("https://www.amazon.com")
      time.sleep(5)
      self.driver.execute_script("window.scrollTo(0,3000)")
    
      #can't login because of OTP
      #self.driver.find_element(By.CSS_SELECTOR, "#XSxnGG_-a2X5p1gGqNy5UQ-product-carousel .feed-carousel-card:nth-child(4) .product-image").click()
      #self.driver.find_element(By.CSS_SELECTOR, "#color_name_2_price > .a-size-mini").click()
      #element = self.driver.find_element(By.CSS_SELECTOR, "#a-autoid-19-announce .imgSwatch")
      #time.sleep(3)
      self.driver.execute_script("window.scrollTo(0,1800)")
      element = self.driver.find_element(By.LINK_TEXT, "Try Prime")

      self.driver.find_element(By.LINK_TEXT, "Today\'s Deals").click()
      #element = self.driver.find_element(By.CSS_SELECTOR, "#\\31 03_dealView_2 #dealImage .a-row:nth-child(2)")

      self.driver.execute_script("window.scrollTo(0,276)")
      element = self.driver.find_element(By.CSS_SELECTOR, "body")
      self.driver.find_element(By.CSS_SELECTOR, "#\\31 03_dealView_18 .a-section > .a-row").click()
      self.driver.find_element(By.CSS_SELECTOR, "#\\31 02_dealView_1 #dealImage .a-row:nth-child(2)").click()
    except Exception as E:
      self.driver.delete_all_cookies()
      # self.teardown_method('GET')
      print(E)
      pass

  def shopee(self):
    self.driver.set_page_load_timeout(25)
    try:
      print("[*] Shopee (E-commerce)")
      self.driver.get("https://shopee.vn/")
      time.sleep(3)
     
      #self.driver.find_element(By.CSS_SELECTOR, ".image-carousel__item:nth-child(3) .home-category-list__category-grid:nth-child(1) .\\_3ZDC1p > .SpPcVL").click()
      time.sleep(3)
      
      #self.driver.find_element(By.CSS_SELECTOR, ".image-carousel__item:nth-child(1) .ofs-carousel__item:nth-child(1) .ofs-carousel__cover-image").click()
      time.sleep(3)

      self.driver.execute_script("window.scrollTo(1000,2000)")
      time.sleep(2)
      # 8 | click | css=.image-carousel__item:nth-child(1) .lazy-image__image:nth-child(1) |  | 
      self.driver.find_element(By.CSS_SELECTOR, ".image-carousel__item:nth-child(1) .lazy-image__image:nth-child(1)").click()
      time.sleep(2)
      self.driver.find_element(By.CSS_SELECTOR, ".page-product").click()
      time.sleep(2)
      element = self.driver.find_element(By.CSS_SELECTOR, ".icon-arrow-right-bold")
      actions = ActionChains(self.driver)
      actions.move_to_element(element).perform()
    except Exception as E:
      self.driver.delete_all_cookies()
      # self.teardown_method('GET')
      print(E)
      pass
  
  def twitter(self):
    self.driver.set_page_load_timeout(25)
    try:
      print("[*] Twitter (Social Network)")
      self.driver.get("https://twitter.com/")
      time.sleep(5)
      #self.driver.find_element(By.XPATH, "//input[@value=\'Log in\']").click()
      time.sleep(2)
      self.driver.find_element(By.CSS_SELECTOR, ".js-username-field").click()
      self.driver.find_element(By.CSS_SELECTOR, ".js-username-field").send_keys("")   #username
      self.driver.find_element(By.CSS_SELECTOR, ".js-password-field").send_keys("")   #password
      self.driver.find_element(By.CSS_SELECTOR, ".js-password-field").send_keys(Keys.ENTER)
      time.sleep(2)
      self.driver.execute_script("window.scrollTo(0,1380)")
      time.sleep(5)
      self.driver.find_element(By.XPATH, "/html/body/div/div/div/div/header/div/div/div/div/div[2]/nav/div").click()
      time.sleep(2)
      self.driver.find_element(By.XPATH, "//div[@id=\'react-root\']/div/div/div/div/div/div[2]/div[3]/div/div/div/div/div[13]/a/div").click()
      time.sleep(2)
      self.driver.find_element(By.CSS_SELECTOR, ".css-18t94o4:nth-child(2) > .css-901oao > .css-901oao > .css-901oao").click()
      time.sleep(2)
    except Exception as E:
      self.driver.delete_all_cookies()
      # self.teardown_method('GET')
      print(E)
      pass
  
  def norton(self):
    self.driver.set_page_load_timeout(35)   
    try:
      print("[*] Norton (Anti Virus)")
      self.driver.execute_script("window.open('https://norton.com')")
      self.driver.switch_to.window(self.driver.window_handles[2])
    except Exception as E:
      self.driver.delete_all_cookies()
      # self.teardown_method('GET')
      print(E)
      pass

  def bitdefender(self):   
    self.driver.set_page_load_timeout(25)
    try:
      print("[*] Bitdefender (Anti Virus)")
      self.driver.get('https://www.bitdefender.com/Downloads/')
      
    except Exception as E:
      self.driver.delete_all_cookies()
      # self.teardown_method('GET')
      print(E)
      pass
  
  def kaspersky(self):   
    self.driver.set_page_load_timeout(25)
    try:
      print("[*] Kaspersky (Anti Virus)")
      self.driver.get('https://www.kaspersky.com.vn/')
      
    except Exception as E:
      self.driver.delete_all_cookies()
      # self.teardown_method('GET')
      print(E)
      pass
    
  def eset(self):  
    self.driver.set_page_load_timeout(25) 
    try:
      print("[*] Eset (Anti Virus)")
      self.driver.get('https://www.eset.com/int/home/free-trial/')
      
    except Exception as E:
      self.driver.delete_all_cookies()
      # self.teardown_method('GET')
      print(E)
      pass
