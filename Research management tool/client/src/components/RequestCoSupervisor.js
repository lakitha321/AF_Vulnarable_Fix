import React,{useState, useEffect, useContext} from "react";
import axios from "axios";
import {BrowserRouter as Router, Link} from 'react-router-dom';
import { useNavigate } from 'react-router-dom';
import { confirm } from "react-confirm-box";
import Card from "react-bootstrap/Card";

import { UserContext } from "../App";

export default function AllStaff(){

    const navigate = useNavigate();

    const {state, dispatch} = useContext(UserContext);
    dispatch({type:"USER", payload:1});

    const grpID = localStorage.getItem("sgroupid");
    const topic = window.localStorage.getItem('topic');

    const [staffArr, setStaff] = useState([]);
    const [requests, setRequest] = useState([]);
    

    useEffect(() => {
        function getStaff(){
            axios.get("http://localhost:8070/staff/getcosup").then((res) => {
                setStaff(res.data);
            }).catch((err) => {
                alert(err);
            })
        }
        function getRequest(){
            axios.get(`http://localhost:8070/request/${grpID}`).then((res) => {
                setRequest(res.data);
            }).catch((err) => {
                alert(err);
            })
        }
        getStaff();
        getRequest();
    }, []);

    const saveRequest = async(stf) => {
        
        const grp = grpID;
        const Staff = stf;

        const newRequest = {
            grp,
            Staff,
            topic
        }

        axios.post('http://localhost:8070/request/add', newRequest).then((res) => {
            alert(res.data);
            window.location.reload(false);
        }).catch((err) => {
            alert(err);
        });
    }

    const deleteRequest = async(id) => {
        axios.delete(`http://localhost:8070/request/delete/${id}`).then((res) => {
            alert(res.data);
            window.location.reload(false);
        }).catch((err) => {
            alert(err);
        });
    }
    

    return(
        <div className="container">
            <br/><br/><br/>
            <div align='center'>
                {
                       requests.map((val, key) => {
                            return(
                                <>
                                <div className="col-12" align="center" key={val._id}>
                                    <Card style={{ width: '60rem', backgroundColor: 'transparent', borderColor: 'white' }}>
                                    <Card.Body>
                                    <Card.Subtitle align="right">
                                        <button type="button" class="btn btn-danger" style={{width: '3rem'}} onClick={() => {deleteRequest(val._id)}}>
                                        <svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" fill="currentColor" class="bi bi-x-lg" viewBox="0 0 16 16">
                                        <path d="M2.146 2.854a.5.5 0 1 1 .708-.708L8 7.293l5.146-5.147a.5.5 0 0 1 .708.708L8.707 8l5.147 5.146a.5.5 0 0 1-.708.708L8 8.707l-5.146 5.147a.5.5 0 0 1-.708-.708L7.293 8 2.146 2.854Z"/>
                                        </svg>
                                        </button>
                                    </Card.Subtitle>
                                    <Card.Title align="center" style={{ color: 'white'}}>Requested on : {val.time}</Card.Title>
                                    <Card.Text align="center" style={{ color: 'white'}}>Group : {val.grp}</Card.Text>
                                    <Card.Text align="center" style={{ color: 'white'}}>Topic choosen : {val.topic}</Card.Text>
                                    <Card.Text align="center" style={{ color: 'white'}}>Requested Supervisor : {val.Staff}</Card.Text>
                                        {val.status === "Pending..." ? (
                                            <>
                                                <Card.Subtitle align="center" style={{ color: 'yellow'}}>Request is {val.status}</Card.Subtitle>
                                            </>
                                        ):(
                                            <>
                                                {val.status === "Rejected" ? (
                                                    <>
                                                        <Card.Subtitle align="center" style={{ color: 'red'}}>Request was {val.status}</Card.Subtitle>
                                                    </>
                                                ):(
                                                    <>
                                                        <Card.Subtitle align="center" style={{ color: 'lime'}}>Request was {val.status}</Card.Subtitle>
                                                    </>
                                                )}
                                            </>
                                        )}
                                        {val.feedback ? (
                                        <>
                                            <Card.Text align="center" style={{ color: 'white'}}>Feedback : {val.feedback}</Card.Text>
                                        </>
                                    ):(
                                        <>
                                        </>
                                    )}
                                    </Card.Body>
                                    </Card><br/><br/>
                                </div>
                                </>
                            )
                       })
                   }
            </div>
            <br/><br/>
            <p className="fs-2" style={{ color: 'white'}}>&nbsp;&nbsp;&nbsp;Co-supervisors</p>
           <table className="table table-hover mt-3" style={{ color: 'white'}}>
               <thead>
                   <tr>
                   <th>Name</th>
                    <th>Email</th>
                    <th>Role</th>
                    <th>R area</th>
                   </tr>
               </thead>
               <tbody>
                   {
                       staffArr.map((val, key) => {
                            return(
                                <tr key={val._id}>
                                    <td>{val.name}</td>
                                    <td>{val.email}</td>
                                    <td>{val.role}</td>
                                    <td>{val.research}</td>
                                    <td align="right" style={{width:'18px'}}>
                                        <button type="button" class="btn btn-success" onClick={() => saveRequest(val.email)}>
                                            Request
                                        </button>
                                    </td>
                                </tr>
                            )
                       })
                   }
               </tbody>
           </table>
        </div>
    )

}