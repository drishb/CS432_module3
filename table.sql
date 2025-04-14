create database DBMS_PROJECT;
use DBMS_PROJECT;
--create tables
CREATE TABLE warden (
  `warden_id` int NOT NULL AUTO_INCREMENT,
  `name` varchar(100) NOT NULL,
  `contact` varchar(15) DEFAULT NULL,
  `email` varchar(100) NOT NULL,
  PRIMARY KEY (`warden_id`)
);

CREATE TABLE hostel (
  `hostel_id` int NOT NULL,
  `name` varchar(1) NOT NULL,
  `total_rooms` int DEFAULT NULL,
  `Warden_ID` int DEFAULT NULL,
  PRIMARY KEY (`hostel_id`),
  UNIQUE KEY `name` (`name`),
  UNIQUE KEY `Warden_ID` (`Warden_ID`),
  CONSTRAINT `fk_hostel_warden` FOREIGN KEY (`Warden_ID`) REFERENCES `warden` (`warden_id`) ON DELETE SET NULL,
  CONSTRAINT `chk_hname` CHECK ((`name` in (_utf8mb4'A',_utf8mb4'B',_utf8mb4'C',_utf8mb4'D',_utf8mb4'E',_utf8mb4'F',_utf8mb4'G',_utf8mb4'H',_utf8mb4'I',_utf8mb4'J',_utf8mb4'K',_utf8mb4'L'))),
  CONSTRAINT `hostel_chk_1` CHECK ((`total_rooms` > 0))
) ;

CREATE TABLE room (
  `room_id` int NOT NULL,
  `room_type` enum('single','double','triple') NOT NULL,
  `status` enum('vacant','occupied') DEFAULT NULL,
  `Hostel_ID` int NOT NULL,
  PRIMARY KEY (`room_id`),
  KEY `fk_room_hostel` (`Hostel_ID`),
  CONSTRAINT `fk_room_hostel` FOREIGN KEY (`Hostel_ID`) REFERENCES `hostel` (`hostel_id`) ON DELETE CASCADE
) ;


CREATE TABLE student (
  `student_id` int NOT NULL,
  `name` varchar(50) NOT NULL,
  `age` int DEFAULT NULL,
  `email` varchar(50) NOT NULL,
  `contact_no` varchar(10) NOT NULL,
  `Room_ID` int NOT NULL,
  `Hostel_ID` int NOT NULL,
  PRIMARY KEY (`student_id`),
  UNIQUE KEY `email` (`email`),
  UNIQUE KEY `contact_no` (`contact_no`),
  KEY `fk_student_room` (`Room_ID`),
  KEY `fk_student_hostel` (`Hostel_ID`),
  CONSTRAINT `fk_student_hostel` FOREIGN KEY (`Hostel_ID`) REFERENCES `hostel` (`hostel_id`) ON DELETE CASCADE,
  CONSTRAINT `fk_student_room` FOREIGN KEY (`Room_ID`) REFERENCES `room` (`room_id`) ON DELETE CASCADE
) ;


CREATE TABLE complaints (
  `complaint_no` int NOT NULL,
  `complaint_date` date NOT NULL,
  `category` enum('Civil','electrical','AC','water cooler','noise','roommate') NOT NULL,
  `status` enum('Resolved','Not Resolved') DEFAULT 'Not Resolved',
  `Student_ID` int NOT NULL,
  PRIMARY KEY (`complaint_no`),
  KEY `fk_complaints_student` (`Student_ID`),
  CONSTRAINT `fk_complaints_student` FOREIGN KEY (`Student_ID`) REFERENCES `student` (`student_id`) ON DELETE CASCADE
) ;
-- adding new columns in table compLaint
ALTER TABLE complaints ADD COLUMN complaint_details varchar(255);
ALTER TABLE complaints ADD COLUMN subject varchar(100);

CREATE TABLE visitors (
  `visitor_id` int NOT NULL AUTO_INCREMENT,
  `name` varchar(100) NOT NULL,
  `contact` varchar(15) DEFAULT NULL,
  `in_time` timestamp NULL DEFAULT CURRENT_TIMESTAMP,
  `out_time` timestamp NULL DEFAULT NULL,
  `Student_ID` int NOT NULL,
  PRIMARY KEY (`visitor_id`),
  KEY `fk_visitors_student` (`Student_ID`),
  CONSTRAINT `fk_visitors_student` FOREIGN KEY (`Student_ID`) REFERENCES `student` (`student_id`) ON DELETE CASCADE,
);


CREATE TABLE paymentsfee (
  `payment_id` int NOT NULL,
  `amount` decimal(10,2) NOT NULL,
  `due_date` date NOT NULL,
  `status` enum('Pending','Paid') DEFAULT 'Pending',
  `Student_ID` int NOT NULL,
  PRIMARY KEY (`payment_id`),
  KEY `fk_paymentsfee_student` (`Student_ID`),
  CONSTRAINT `fk_paymentsfee_student` FOREIGN KEY (`Student_ID`) REFERENCES `student` (`student_id`) ON DELETE CASCADE
); 

CREATE TABLE inventory (
  `item_id` int NOT NULL AUTO_INCREMENT,
  `item_name` varchar(100) NOT NULL,
  `quantity` int NOT NULL,
  `i_condition` enum('Good','Fair','Poor') NOT NULL,
  `Hostel_ID` int NOT NULL,
  PRIMARY KEY (`item_id`),
  KEY `fk_inventory_hostel` (`Hostel_ID`),
  CONSTRAINT `fk_inventory_hostel` FOREIGN KEY (`Hostel_ID`) REFERENCES `hostel` (`hostel_id`) ON DELETE CASCADE
) ;

CREATE TABLE allocation (
  `allocation_id` int NOT NULL AUTO_INCREMENT,
  `start_date` date NOT NULL,
  `end_date` date DEFAULT NULL,
  `Student_ID` int NOT NULL,
  `Room_ID` int NOT NULL,
  `Hostel_ID` int NOT NULL,
  PRIMARY KEY (`allocation_id`),
  KEY `fk_allocation_student` (`Student_ID`),
  KEY `fk_allocation_room` (`Room_ID`),
  KEY `fk_allocation_hostel` (`Hostel_ID`),
  CONSTRAINT `fk_allocation_hostel` FOREIGN KEY (`Hostel_ID`) REFERENCES `hostel` (`hostel_id`) ON DELETE CASCADE,
  CONSTRAINT `fk_allocation_room` FOREIGN KEY (`Room_ID`) REFERENCES `room` (`room_id`) ON DELETE CASCADE,
  CONSTRAINT `fk_allocation_student` FOREIGN KEY (`Student_ID`) REFERENCES `student` (`student_id`) ON DELETE CASCADE
);

CREATE TABLE visitors_log (
  `log_id` int NOT NULL AUTO_INCREMENT,
  `visit_date` timestamp NULL DEFAULT CURRENT_TIMESTAMP,
  `Visitor_ID` int NOT NULL,
  `Student_ID` int NOT NULL,
  PRIMARY KEY (`log_id`),
  KEY `fk_logs_visitor` (`Visitor_ID`),
  KEY `fk_logs_student` (`Student_ID`),
  CONSTRAINT `fk_logs_student` FOREIGN KEY (`Student_ID`) REFERENCES `student` (`student_id`) ON DELETE CASCADE,
  CONSTRAINT `fk_logs_visitor` FOREIGN KEY (`Visitor_ID`) REFERENCES `visitors` (`visitor_id`) ON DELETE CASCADE
);

CREATE TABLE members (
  `MemberID` int NOT NULL AUTO_INCREMENT,
  `Name` varchar(100) NOT NULL,
  `Image` varchar(255) DEFAULT NULL,
  `Age` int DEFAULT NULL,
  `Email` varchar(100) NOT NULL,
  `ContactNumber` varchar(20) NOT NULL,
  PRIMARY KEY (`MemberID`),
  UNIQUE KEY `Email` (`Email`),
  UNIQUE KEY `ContactNumber` (`ContactNumber`),
  CONSTRAINT `member_chk_1` CHECK ((`Age` >= 18))
) ;


show tables;
-- inserting data

INSERT INTO warden VALUES (1,'Dr. Rajesh Kumar','9876543210','rajesh.kumar@hostel.com'),(2,'Ms. Anjali Mehta','8765432109','anjali.mehta@hostel.com'),(3,'Mr. Suresh Raina','7654321098','suresh.raina@hostel.com'),(4,'Dr. Priya Sharma','6543210987','priya.sharma@hostel.com'),(5,'Mr. Aman Verma','5432109876','aman.verma@hostel.com'),(6,'Ms. Sneha Kapoor','4321098765','sneha.kapoor@hostel.com'),(7,'Dr. Vivek Choudhary','3210987654','vivek.choudhary@hostel.com'),(8,'Mr. Neeraj Gupta','2109876543','neeraj.gupta@hostel.com'),(9,'Ms. Pooja Das','1098765432','pooja.das@hostel.com'),(10,'Mr. Arvind Singh','9876012345','arvind.singh@hostel.com'),(11,'Dr. Meena Agarwal','8765023456','meena.agarwal@hostel.com'),(12,'Ms. Kavita Nair','7654034567','kavita.nair@hostel.com');

INSERT INTO hostel VALUES (1,'A',50,1),(2,'B',60,2),(3,'C',45,3),(4,'D',70,4),(5,'E',55,5),(6,'F',65,6),(7,'G',40,7),(8,'H',75,8),(9,'I',50,9),(10,'J',80,10),(11,'K',60,11),(12,'L',90,12);

INSERT INTO room VALUES (101,'single','vacant',1),(102,'double','occupied',1),(103,'triple','vacant',2),(104,'single','occupied',2),(105,'double','vacant',3),(106,'triple','occupied',3),(107,'single','vacant',4),(108,'double','occupied',5),(109,'triple','vacant',6),(110,'single','occupied',7),(111,'double','vacant',8),(112,'triple','occupied',9),(113,'single','vacant',10),(114,'double','occupied',10),(115,'triple','vacant',11),(116,'single','occupied',11),(117,'double','vacant',12),(118,'triple','occupied',12),(119,'single','vacant',1),(120,'double','occupied',2),(121,'triple','vacant',3),(122,'single','occupied',4);

INSERT INTO student VALUES (1,'Rahul Sharma',20,'rahul.sharma1@email.com','9876543210',101,1),(2,'Anjali Mehta',19,'anjali.mehta@email.com','8765432109',102,1),(3,'Suresh Raina',21,'suresh.raina@email.com','7654321098',103,2),(4,'Priya Sharma',22,'priya.sharma@email.com','6543210987',104,2),(5,'Aman Verma',23,'aman.verma@email.com','5432109876',105,3),(6,'Sneha Kapoor',20,'sneha.kapoor@email.com','4321098765',106,3),(7,'Vivek Choudhary',19,'vivek.choudhary@email.com','3210987654',107,4),(8,'Neeraj Gupta',21,'neeraj.gupta@email.com','2109876543',108,5),(9,'Pooja Das',20,'pooja.das@email.com','1098765432',109,6),(10,'Arvind Singh',22,'arvind.singh@email.com','9876012345',110,7),(11,'Meena Agarwal',19,'meena.agarwal@email.com','8765023456',111,8),(12,'Kavita Nair',20,'kavita.nair@email.com','7654034567',112,9),(13,'Rohan Mishra',21,'rohan.mishra@email.com','7543021234',113,10),(14,'Ishita Malhotra',22,'ishita.malhotra@email.com','6432012345',114,10),(15,'Aditya Jaiswal',20,'aditya.jaiswal@email.com','5321012346',115,11),(16,'Simran Kaur',19,'simran.kaur@email.com','4210987653',116,11),(17,'Yash Dubey',22,'yash.dubey@email.com','3109876542',117,12),(18,'Divya Bhardwaj',21,'divya.b@email.com','2098765431',118,12),(19,'Tarun Yadav',23,'tarun.yadav@email.com','1987654320',119,1),(20,'Snehal Joshi',20,'snehal.joshi@email.com','9876543201',120,2),(21,'Gaurav Taneja',21,'gaurav.t@email.com','8765432102',121,3),(22,'Manisha Rao',19,'manisha.rao@email.com','7654321033',122,4),(23,'Mohit Sharma',22,'mohit.sharma@email.com','6543210984',101,1),(24,'Aditi Sen',20,'aditi.sen@email.com','5432109875',102,1),(25,'Raghav Bansal',21,'raghav.b@email.com','4321098766',103,2),(26,'Nidhi Patel',19,'nidhi.patel@email.com','3210987657',104,2),(27,'Aakash Tiwari',22,'aakash.tiwari@email.com','2109876548',105,3),(28,'Swati Desai',20,'swati.desai@email.com','1098765439',106,3),(29,'Sakshi Jain',19,'sakshi.jain@email.com','9876543200',107,4),(30,'Ravi Kumar',21,'ravi.kumar@email.com','8765432101',108,5),(31,'Neha Goyal',20,'neha.goyal@email.com','7654321002',109,6),(32,'Vikram Solanki',22,'vikram.solanki@email.com','6543210993',110,7);

INSERT INTO allocation VALUES (1,'2024-06-01','2024-12-01',1,101,1),(2,'2024-06-02',NULL,2,102,1),(3,'2024-06-03','2025-01-15',3,103,2),(4,'2024-06-04',NULL,4,104,2),(5,'2024-06-05','2024-11-30',5,105,3),(6,'2024-06-06',NULL,6,106,3),(7,'2024-06-07','2024-10-20',7,107,4),(8,'2024-06-08',NULL,8,108,5),(9,'2024-06-09','2025-02-01',9,109,6),(10,'2024-06-10',NULL,10,110,7),(11,'2024-06-11','2024-12-10',11,111,8),(12,'2024-06-12',NULL,12,112,9),(13,'2024-06-13','2025-01-01',13,113,10),(14,'2024-06-14',NULL,14,114,10),(15,'2024-06-15','2024-09-30',15,115,11),(16,'2024-06-16',NULL,16,116,11),(17,'2024-06-17','2025-03-01',17,117,12),(18,'2024-06-18',NULL,18,118,12),(19,'2024-06-19','2024-08-31',19,119,1),(20,'2024-06-20',NULL,20,120,2),(21,'2024-06-21','2024-10-05',21,121,3),(22,'2024-06-22',NULL,22,122,4),(23,'2024-06-23','2025-01-20',23,101,1),(24,'2024-06-24',NULL,24,102,1),(25,'2024-06-25','2024-11-15',25,103,2),(26,'2024-06-26',NULL,26,104,2),(27,'2024-06-27','2025-02-10',27,105,3),(28,'2024-06-28',NULL,28,106,3),(29,'2024-06-29','2024-09-20',29,107,4),(30,'2024-06-30',NULL,30,108,5),(31,'2024-07-01','2025-04-01',31,109,6),(32,'2024-07-02',NULL,32,110,7);

INSERT INTO complaints VALUES (1,'2025-02-01','Civil','Not Resolved',1),(2,'2025-02-02','electrical','Resolved',2),(3,'2025-02-03','AC','Not Resolved',3),(4,'2025-02-04','water cooler','Resolved',4),(5,'2025-02-05','noise','Not Resolved',5),(6,'2025-02-06','roommate','Resolved',6),(7,'2025-02-07','Civil','Not Resolved',7),(8,'2025-02-08','electrical','Resolved',8),(9,'2025-02-09','AC','Not Resolved',9),(10,'2025-02-10','water cooler','Resolved',10),(11,'2025-02-11','noise','Not Resolved',11),(12,'2025-02-12','roommate','Resolved',12),(13,'2025-02-13','Civil','Not Resolved',13),(14,'2025-02-14','electrical','Resolved',14),(15,'2025-02-15','AC','Not Resolved',15);

INSERT INTO inventory VALUES (1,'Study Table',20,'Good',1),(2,'Chairs',40,'Fair',1),(3,'Beds',50,'Good',2),(4,'Mattresses',50,'Good',2),(5,'Ceiling Fans',20,'Fair',3),(6,'Water Coolers',5,'Good',3),(7,'Cupboards',25,'Fair',4),(8,'Sofas',10,'Good',4),(9,'LED Lights',30,'Good',5),(10,'Curtains',20,'Fair',5),(11,'Dining Tables',5,'Good',6),(12,'CCTV Cameras',8,'Good',6),(13,'Emergency Lights',15,'Fair',7),(14,'Fire Extinguishers',10,'Good',7),(15,'Desks',30,'Fair',8),(16,'Bookshelves',20,'Good',8),(17,'Laundry Machines',4,'Good',9),(18,'Ironing Stations',6,'Fair',9),(19,'Computers',12,'Good',10),(20,'Printers',4,'Fair',10),(21,'Refrigerators',6,'Good',11),(22,'Microwaves',5,'Fair',11),(23,'Air Conditioners',10,'Good',12);

INSERT INTO members VALUES (24210033,'Drishti Bhandari','.....',23,'24210033@iitgn.ac.in','7452011688'),(24210057,'Krishan Sharma','.....',24,'24210057@iitgn.ac.in','9983878390'),(24210093,'Shashwat Pandey','.....',24,'24210093@iitgn.ac.in','8077601583');

INSERT INTO payments VALUES (1,5000.00,'2025-03-01','Pending',1),(2,5200.00,'2025-03-01','Paid',2),(3,4800.00,'2025-03-01','Pending',3),(4,5000.00,'2025-03-01','Paid',4),(5,5100.00,'2025-03-01','Pending',5),(6,4950.00,'2025-03-01','Paid',6),(7,5300.00,'2025-03-01','Pending',7),(8,5000.00,'2025-03-01','Paid',8),(9,5200.00,'2025-03-01','Pending',9),(10,4800.00,'2025-03-01','Paid',10),(11,5050.00,'2025-03-01','Pending',11),(12,5000.00,'2025-03-01','Paid',12),(13,5300.00,'2025-03-01','Pending',13),(14,4950.00,'2025-03-01','Paid',14),(15,5100.00,'2025-03-01','Pending',15),(16,5200.00,'2025-03-01','Paid',16),(17,4800.00,'2025-03-01','Pending',17),(18,5000.00,'2025-03-01','Paid',18),(19,5050.00,'2025-03-01','Pending',19),(20,5000.00,'2025-03-01','Paid',20),(21,5300.00,'2025-03-01','Pending',21),(22,4950.00,'2025-03-01','Paid',22),(23,5100.00,'2025-03-01','Pending',23),(24,5200.00,'2025-03-01','Paid',24),(25,4800.00,'2025-03-01','Pending',25),(26,5000.00,'2025-03-01','Paid',26),(27,5050.00,'2025-03-01','Pending',27),(28,5000.00,'2025-03-01','Paid',28),(29,5300.00,'2025-03-01','Pending',29),(30,4950.00,'2025-03-01','Paid',30),(31,5100.00,'2025-03-01','Pending',31),(32,5200.00,'2025-03-01','Paid',32);

INSERT INTO visitors VALUES (1,'Amit Verma','9876543210','2025-02-01 04:30:00','2025-02-01 06:30:00',1,1),(2,'Rakesh Kumar','8765432109','2025-02-02 06:00:00','2025-02-02 07:45:00',2,2),(3,'Sanjay Yadav','7654321098','2025-02-03 08:30:00','2025-02-03 10:30:00',3,3),(4,'Nikita Sharma','6543210987','2025-02-04 03:30:00','2025-02-04 06:00:00',4,4),(5,'Pooja Malhotra','5432109876','2025-02-05 09:30:00','2025-02-05 11:30:00',5,5),(6,'Vikram Singh','4321098765','2025-02-06 03:15:00','2025-02-06 05:15:00',6,6),(7,'Meera Joshi','3210987654','2025-02-07 06:45:00','2025-02-07 08:30:00',7,7),(8,'Rahul Desai','2109876543','2025-02-08 05:00:00','2025-02-08 07:00:00',8,8),(9,'Kiran Patel','1098765432','2025-02-09 09:15:00','2025-02-09 11:15:00',9,9),(10,'Arjun Kapoor','9876012345','2025-02-10 04:00:00','2025-02-10 05:30:00',10,10),(11,'Simran Nair','8765023456','2025-02-11 10:00:00','2025-02-11 12:00:00',11,11),(12,'Manish Bansal','7654034567','2025-02-12 07:30:00','2025-02-12 09:30:00',12,12),(13,'Ravi Shankar','7543021234','2025-02-13 04:30:00',NULL,13,1),(14,'Swati Gupta','6432012345','2025-02-14 08:30:00',NULL,14,2);

INSERT INTO visitors_log VALUES (1,'2025-02-01 05:00:00',1,1),(2,'2025-02-02 06:15:00',2,2),(3,'2025-02-03 08:45:00',3,3),(4,'2025-02-04 04:20:00',4,4),(5,'2025-02-05 10:35:00',5,5),(6,'2025-02-06 03:00:00',6,6),(7,'2025-02-07 06:50:00',7,7),(8,'2025-02-08 04:40:00',8,8),(9,'2025-02-09 10:10:00',9,9),(10,'2025-02-10 03:55:00',10,10),(11,'2025-02-11 11:15:00',11,11),(12,'2025-02-12 07:40:00',12,12),(13,'2025-02-13 04:30:00',13,13),(14,'2025-02-14 09:00:00',14,14);

select * from student;


