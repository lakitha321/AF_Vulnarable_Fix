import React,{useState, useEffect, useContext} from "react";
import axios from "axios";
import {BrowserRouter as Router, Link} from 'react-router-dom';
import { useNavigate } from 'react-router-dom';
import { confirm } from "react-confirm-box";

import { UserContext } from "../App";

const deleteSubmission = async (id) => {
    const result1 = await confirm("Are you sure do you want to delete this submission?");
    if (result1) {
        console.log(id);
        axios.delete(`http://localhost:8070/submission/delete/${id}`).then((res) => {
            alert(res.data);
            window.location.assign("/allsubmissions");
        }).catch((err) => {
            alert(err);
        });
    }
    
}

export default function AllSubmissions(){

    const navigate = useNavigate();

    const {state, dispatch} = useContext(UserContext);
    dispatch({type:"USER", payload:2})

    const [submissionArr, setSubmission] = useState([]);
    

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

    function passValues(id, name, desc, deadline){
        navigate(`/updatesubmission/${id}/${name}/${desc}/${deadline}`);
    }
    

    return(
        <div className="container my-5" >
            <Link to="/createsubmission">
            <button type="button" class="btn btn-success">Create submission</button>
            </Link>
            &nbsp;&nbsp;
            <Link to="/submittedfiles">
            <button type="button" class="btn btn-light">View submitted files</button>
            </Link>
            <div>
           <table className="table table-hover mt-3" style={{ color: 'white'}}>
               <thead>
                   <tr>
                    <th>#</th>
                    <th>Name</th>
                    <th>Description</th>
                    <th>Deadline</th>
                    <th>Panel access?</th>
                    <th ></th>
                   </tr>
               </thead>
               <tbody>
                   {
                       submissionArr.map((val, key) => {
                            return(
                                <tr key={val._id}>
                                    <th>{key + 1}</th>
                                    <td>{val.name}</td>
                                    <td>{val.desc}</td>
                                    <td>{val.deadline}</td>
                                    <td>{val.panel}</td>
                                    <td align="right">
                                        <button type="button" class="btn btn-primary" style={{opacity: "70%"}} onClick={() => passValues(val._id, val.name, val.desc, val.deadline)}>
                                        <svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" fill="currentColor" class="bi bi-pencil-square" viewBox="0 0 16 16">
                                        <path d="M15.502 1.94a.5.5 0 0 1 0 .706L14.459 3.69l-2-2L13.502.646a.5.5 0 0 1 .707 0l1.293 1.293zm-1.75 2.456-2-2L4.939 9.21a.5.5 0 0 0-.121.196l-.805 2.414a.25.25 0 0 0 .316.316l2.414-.805a.5.5 0 0 0 .196-.12l6.813-6.814z"/>
                                        <path fill-rule="evenodd" d="M1 13.5A1.5 1.5 0 0 0 2.5 15h11a1.5 1.5 0 0 0 1.5-1.5v-6a.5.5 0 0 0-1 0v6a.5.5 0 0 1-.5.5h-11a.5.5 0 0 1-.5-.5v-11a.5.5 0 0 1 .5-.5H9a.5.5 0 0 0 0-1H2.5A1.5 1.5 0 0 0 1 2.5v11z"/>
                                        </svg>
                                        </button>
                                        &nbsp;&nbsp;
                                        <button type="button" class="btn btn-danger" style={{opacity: "70%"}} onClick={() => deleteSubmission(val._id)}>
                                        <svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" fill="currentColor" class="bi bi-trash3" viewBox="0 0 16 16">
                                        <path d="M6.5 1h3a.5.5 0 0 1 .5.5v1H6v-1a.5.5 0 0 1 .5-.5ZM11 2.5v-1A1.5 1.5 0 0 0 9.5 0h-3A1.5 1.5 0 0 0 5 1.5v1H2.506a.58.58 0 0 0-.01 0H1.5a.5.5 0 0 0 0 1h.538l.853 10.66A2 2 0 0 0 4.885 16h6.23a2 2 0 0 0 1.994-1.84l.853-10.66h.538a.5.5 0 0 0 0-1h-.995a.59.59 0 0 0-.01 0H11Zm1.958 1-.846 10.58a1 1 0 0 1-.997.92h-6.23a1 1 0 0 1-.997-.92L3.042 3.5h9.916Zm-7.487 1a.5.5 0 0 1 .528.47l.5 8.5a.5.5 0 0 1-.998.06L5 5.03a.5.5 0 0 1 .47-.53Zm5.058 0a.5.5 0 0 1 .47.53l-.5 8.5a.5.5 0 1 1-.998-.06l.5-8.5a.5.5 0 0 1 .528-.47ZM8 4.5a.5.5 0 0 1 .5.5v8.5a.5.5 0 0 1-1 0V5a.5.5 0 0 1 .5-.5Z"/>
                                        </svg>
                                        </button>
                                    </td>
                                </tr>
                            )
                       })
                   }
               </tbody>
           </table>
           </div>
        </div>
    )

}