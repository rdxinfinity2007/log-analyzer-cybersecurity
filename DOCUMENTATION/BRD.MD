**📄 4. BRD – Backend Requirement Document**  

===

## **Backend implemented using Python.**



**Backend Modules**

---

##### **1️⃣ Log Parser**

* **File:   log\_parser.py**

  ---
* **Functions:**



**parse\_logs()**

**extract\_ip()**

**extract\_username()**

**extract\_status()**



###### **2️⃣ Database Module**

* ###### **Database:   SQLite**



* **File:  database.py**

  ---
* ###### **Table structure:**



**logs**

**----------------------**

**timestamp**

**username**

**ip\_address**

**status**


---

###### **3️⃣ Threat Detection Engine**

###### **File:  threat\_detector.py**



###### **Detects:**



* **multiple failed logins**



* **brute force attacks**



* **abnormal login frequency**



* **suspicious usernames**



###### **4️⃣ AI Engine**



* ###### **File:   anomaly\_detector.py**



###### **Uses:-**

###### 

* ###### **Isolation Forest**

###### 

###### **from:**

###### 

###### **( scikit-learn )**

###### 

###### **5️⃣ Report Generator**

###### **Creates:**

###### 

* ###### **threat\_report.txt**
* ###### **anomaly\_report.txt**
* ###### **anomaly\_results.csv**
