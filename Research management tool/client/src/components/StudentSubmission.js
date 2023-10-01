import React,{useState, useEffect, useContext } from "react";
import axios from "axios";
import { useNavigate } from 'react-router-dom';
import Card from "react-bootstrap/Card";

import { UserContext } from "../App";

export default function StudentSubmissions(){

    const navigate = useNavigate();

    const stgrp = localStorage.getItem("sgroupid");

    const {state1, dispatch} = useContext(UserContext);
    dispatch({type:"USER", payload:1})

    const [submissionArr, setSubmission] = useState([]);

    function passValues(id, name, panel){
        navigate(`/studentsubarea/${id}/${name}/${stgrp}/${panel}`);
    }
    

    useEffect(() => {
        function getSubmissions(){
            axios.get("http://localhost:8070/submission/").then((res) => {
                setSubmission(res.data);
            }).catch((err) => {
                alert(err);
            })
        }
        getSubmissions();
    }, []);

    return(
        <div className="container my-5">
           <div className="row">
                   {
                       submissionArr.map((val, key) => {
                            return(
                                <div className="col-12" align="center" key={val._id}>
                                    <Card style={{ width: '60rem', backgroundColor: 'transparent', borderColor: 'white' }}>
                                    <Card.Body>
                                    <Card.Subtitle align="left" style={{ color: 'white'}}>{key + 1}</Card.Subtitle>
                                        <Card.Title align="center" style={{ color: 'white'}}>{val.name}</Card.Title>
                                        <Card.Subtitle align="center" style={{color:"red"}}>Deadline : {val.deadline}</Card.Subtitle>
                                        <Card.Text align="center" style={{ color: 'white'}}>{val.desc}</Card.Text>
                                        <Card.Text align="center" style={{ color: 'white'}}>Panel access : {val.panel}</Card.Text>
                                        <hr style={{ color: 'white'}} />
                                        <button type="button" class="btn btn-success" style={{width: '20rem'}} onClick={() => passValues(val._id, val.name, val.panel)}>
                                            Check out
                                        </button>
                                        <br/>  
                                    </Card.Body>
                                    </Card><br/><br/>
                                </div>
                            )
                       })
                   }
            </div>
        </div>
    )

}