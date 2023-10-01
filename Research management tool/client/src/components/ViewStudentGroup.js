import React,{useState, useEffect, useContext} from "react";
import axios from "axios";
import Card from "react-bootstrap/Card";
import { Button, Form, Row, Col } from "react-bootstrap";

import { UserContext } from "../App";

export default function StudentGroup(){

    const {state, dispatch} = useContext(UserContext);
    dispatch({type:"USER", payload:1})

    const [studentGrp, setGroup] = useState([]);
    const grpID = localStorage.getItem("sgroupid");

    useEffect(() => {
        function getGroups(){
            axios.get(`http://localhost:8070/studentgroup/get/${grpID}`).then((res) => {
                setGroup(res.data);
            }).catch((err) => {
                alert(err);
            })
        }
        getGroups();
    }, []);

    const [validated, setValidated] = useState(false);
    const [email, setEmail] = useState("");

    const [name, setName] = useState("");
    const member1 = localStorage.getItem("semail");

    const handleSubmit1 = (event) => {
        
        const form1 = event.currentTarget;
        if(form1.checkValidity()==true){
          event.preventDefault();
          event.stopPropagation();
          sendData1();
        }
        else{
          if (form1.checkValidity() == false) {
              event.preventDefault();
              event.stopPropagation();
          }
          
          setValidated(true); 
        }
        
    };
  
    const handleSubmit = (event) => {
        
      const form = event.currentTarget;
      if(form.checkValidity()==true){
        event.preventDefault();
        event.stopPropagation();
        sendData();
      }
      else{
        if (form.checkValidity() == false) {
            event.preventDefault();
            event.stopPropagation();
        }
        
        setValidated(true); 
      }
      
    };

    const sendData1 = (e) => {

        let tempMember = "";

        const groupid = grpID;

        const updateSudentgroup2 = {
            groupid
        }

        axios.get(`http://localhost:8070/student/checkgroupvalidity/${email}`).then((res) => {
            if(res.data){
                if(studentGrp.member2 == "Unknown"){
                    tempMember = "member2";
                }
                else if(studentGrp.member3 == "Unknown"){
                    tempMember = "member3";
                }
                else if(studentGrp.member4 == "Unknown"){
                    tempMember = "member4";
                }
                const updateGrpMember = {
                    tempMember,
                    email
                }

                axios.put(`http://localhost:8070/studentgroup/updatemember/${grpID}`, updateGrpMember).then((res)=>{
                    alert(res.data.msg);
                    alert(res.data.status);   
                    if(res.data.status == true){
                        axios.put(`http://localhost:8070/student/updategroup/${email}`, updateSudentgroup2).then((res3)=>{
                        alert(res3.data.msg);
                        if(res3.data.status){
                            window.location.reload(false); 
                        }
                        }).catch((err)=>{
                            alert(err);
                        })
                    }else{
                        alert("Group updation error")
                    }
                }).catch((err)=>{
                    alert(err);
                })
            }
            else{
                alert("You can only add existing students with no groups!!!");
            }
        }).catch((err) => {
            alert(err);
        })
    }

    const sendData = (e) => {

        let validate = false;

        const newGroup = {
            name,
            member1
        }

        const groupid = name;

        const updateSudentgroup = {
            groupid
        }

        axios.get(`http://localhost:8070/studentgroup/check/${name}`).then((res1)=>{
            validate = res1.data;
            if(validate){
                axios.post(`http://localhost:8070/studentgroup/create`, newGroup).then((res2)=>{
                    alert(res2.data.msg);
                    if(res2.data.status){
                      axios.put(`http://localhost:8070/student/updategroup/${member1}`, updateSudentgroup).then((res3)=>{
                        alert(res3.data.msg);
                        if(res3.data.status){
                            localStorage.setItem("sgroupid", groupid);
                            window.location.reload(false); 
                        }
                        }).catch((err)=>{
                            alert(err);
                        })
                    }
                }).catch((err)=>{
                    alert(err);
                })
            }
            else{
                alert("This group name is already existing!");
            }
        }).catch((err)=>{
            alert(err);
        })
    }

    const [student, setStudent] = useState("");

    useEffect(() => {
        function getStudents(){
            axios.get(`http://localhost:8070/student/getgroup/${member1}`).then((res) => {
                setStudent(res.data);
            }).catch((err) => {
                alert(err);
            })
        }
        getStudents();
    }, []);
    

    return(
        <>
        <br/><br/>
        {student.groupid != "Not defined" ? (
        <div className="col-12" align="center">
        <Card className="mt-3 mb-5" style={{ width: '50rem' }}>
        <Card.Body>
        <Card.Title align="center">{studentGrp.name}</Card.Title>
        <Card.Text align="center">Research topic : {studentGrp.topic}</Card.Text>
        {window.localStorage.setItem('topic', studentGrp.topic)}
        <br/>
        <Card.Text align="left">Member1 : <a href="">{studentGrp.member1}</a></Card.Text>
        <Card.Text align="left">Member2 : <a href="">{studentGrp.member2}</a></Card.Text>
        <Card.Text align="left">Member3 : <a href="">{studentGrp.member3}</a></Card.Text>
        <Card.Text align="left">Member4 : <a href="">{studentGrp.member4}</a></Card.Text>
        <Card.Text align="left">Supervisor : {studentGrp.supervisor}</Card.Text>
        <Card.Text align="left">Co-supervisor : {studentGrp.cosupervisor}</Card.Text>
        <Card.Text align="left">Panel : {studentGrp.panel}</Card.Text>
        {studentGrp.supervisor === "Not defined" ? (
            <>
            
            <div align='center'>
                <a href="/requestsupervisor">
                <button className="btn btn-primary">Request a supervisor</button>
                </a>
            </div>
            <br/><br/>
            </>
        ):(
            <>
            {studentGrp.cosupervisor === "Not defined" ? (
                <>
                
                <div align='center'>
                <a href="/requestcosupervisor">
                    <button className="btn btn-primary">Request a co-supervisor</button>
                </a>
                </div>
                <br/><br/>
                </>
            ):(
                <>
                <a href="grpcht">
                <button className="btn btn-success">Group chat</button>
                </a>
                <br/><br/>
                </>
            )}
            </>
        )}
        {studentGrp.member4 == "Unknown" ? (
            <Form noValidate validated={validated} onSubmit={handleSubmit1}>
            <Row className="mb-3">
                <hr/>
            <p className="fs-5">Add a member</p>
                <Form.Group as={Row} md="5" controlId="validationCustom04">
                    <Form.Label>Member email</Form.Label>
                    <Form.Control type="email" placeholder="Email" pattern="[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}$"
                    onChange={(e) => {
                        setEmail(e.target.value);
                    }}
                    required />
                    <Form.Control.Feedback type="invalid">
                    Please provide a valid Email.
                    </Form.Control.Feedback>
                </Form.Group>
            </Row>
            <Button className="btn btn-success" type="submit" style={{opacity: "70%"}}>Add to group</Button>
            </Form>
        ):(
            <p className="fs-5">Your group reached the maximum capacity</p>
        )}
        </Card.Body>
        </Card>
        </div>
        ):(
            <div className="container mt-5">
            <br/><br/>
            <Card style={{ width: '48rem', margin:"auto" }}>
            <Card.Body>
                <Card.Title>Create a research group</Card.Title>
                <Form noValidate validated={validated} onSubmit={handleSubmit}>
                    <Row className="mb-3">
                    <p className="fs-3" style={{color:"red"}}>Attention!</p>
                        <p>Group name must be unique!</p>
                        <p>You can use only letters and numbers!</p>
                        <p>Group name must contain minimum 5 characters!</p><br/><br/>
                    <Form.Group as={Row} md="5" controlId="validationCustom04">
                        <Form.Control type="text" placeholder="Group name" pattern="[a-zA-Z0-9]{5,}"
                        onChange={(e) => {
                            setName(e.target.value);
                        }}
                        required />
                        <Form.Control.Feedback type="invalid">
                        Please provide a valid Name.
                        </Form.Control.Feedback>
                    </Form.Group>
                    </Row>
                    <Button className="btn btn-success" type="submit" style={{opacity: "70%"}}>Create</Button>
                </Form>
                
            </Card.Body>
            </Card>
            <br/><br/>
            </div>
        )}
        </>
    )

}