import React,{useState, useEffect, useContext} from "react";
import axios from "axios";
import {BrowserRouter as Router, Link} from 'react-router-dom';
import { useNavigate } from 'react-router-dom';
import { confirm } from "react-confirm-box";

import { UserContext } from "../App";

const deleteStaff = async (id) => {
    const result1 = await confirm("Are you sure do you want to delete this Staff member?");
    if (result1) {
        console.log(id);
        axios.delete(`http://localhost:8070/staff/delete/${id}`).then((res) => {
            alert(res.data);
            window.location.assign("/allstaff");
        }).catch((err) => {
            alert(err);
        });
    }
    
}

export default function AllStaff(){

    const navigate = useNavigate();

    const {state, dispatch} = useContext(UserContext);
    dispatch({type:"USER", payload:2})

    const [staffArr, setStaff] = useState([]);

    const [search, setSearch] = useState('');
    

    useEffect(() => {
        function getStaff(){
            axios.get("http://localhost:8070/staff/").then((res) => {
                setStaff(res.data);
            }).catch((err) => {
                alert(err);
            })
        }
        getStaff();
    }, []);

    function passValues(id, name, email, age, gender, nic, address, mobile, password){
        navigate(`/updatestaff/${id}/${name}/${email}/${age}/${gender}/${nic}/${address}/${mobile}/${password}`);
        ///${id}/${name}/${email}/${age}/${gender}/${nic}/${address}/${mobile}/${password}/${role}/${research}
    }

    const updateRole = async (id, cRole, fRole) => {

        if(cRole === fRole){
            alert("Already a ".concat(cRole));
            return;
        }
    
        else{
            navigate(`/udatestaffrole/${id}/${cRole}/${fRole}`);
        }
    }
    

    return(
        <>
            <br/><br/>&nbsp;&nbsp;
            <table style={{width:'100%'}}>
                <tr>
                    <td>
                        &nbsp;&nbsp;&nbsp;
                    <Link to="/staffreg">
                    <button type="button" class="btn btn-success">Register</button>
                    </Link>
                    </td>
                    <td align="right">
                    <input type="text" class="form-control" placeholder="Search by name" style={{backgroundColor : 'transparent', color : 'white' ,borderColor : 'white', width:'20rem' }} onChange={(e) => {setSearch(e.target.value)}}/>
                    </td>
                    <td></td>
                </tr>
            </table>
            
           <table className="table table-hover mt-3" style={{ color: 'white'}}>
               <thead>
                   <tr>
                   <th>Name</th>
                    <th>Email</th>
                    <th>Age</th>
                    <th>Gender</th>
                    <th>NIC</th>
                    <th>Address</th>
                    <th>Mobile</th>
                    <th>Role</th>
                    <th>R area</th>
                   </tr>
               </thead>
               <tbody>
                   {
                       staffArr.map((val, key) => {
                        let x = val.name;
                            return(
                                <>
                                {search ? (
                                    <>
                                    {x.includes(search) ? (
                                        <>
                                        <tr key={val._id}>
                                            <td>{val.name}</td>
                                            <td>{val.email}</td>
                                            <td>{val.age}</td>
                                            <td>{val.gender}</td>
                                            <td>{val.nic}</td>
                                            <td>{val.address}</td>
                                            <td>{val.mobile}</td>
                                            <td>{val.role}</td>
                                            <td>{val.research}</td>
                                            <td align="right" style={{width:'18px'}}>
                                                <div class="btn-group" role="group" aria-label="Basic mixed styles example">
                                                <button type="button" class="btn btn-outline-light" onClick={() => updateRole(val._id, val.role, "Staff member")}>
                                                    Stf
                                                </button>
                                                <button type="button" class="btn btn-outline-light" onClick={() => updateRole(val._id, val.role, "Supervisor")}>
                                                    Su
                                                </button>
                                                <button type="button" class="btn btn-outline-light" onClick={() => updateRole(val._id, val.role, "Co-supervisor")}>
                                                    Co
                                                </button>
                                                <button type="button" class="btn btn-outline-primary" style={{opacity: "70%"}} onClick={() => passValues(val._id, val.name, val.email, val.age, val.gender, val.nic, val.address, val.mobile, val.password)}>
                                                <svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" fill="currentColor" class="bi bi-pencil-square" viewBox="0 0 16 16">
                                                <path d="M15.502 1.94a.5.5 0 0 1 0 .706L14.459 3.69l-2-2L13.502.646a.5.5 0 0 1 .707 0l1.293 1.293zm-1.75 2.456-2-2L4.939 9.21a.5.5 0 0 0-.121.196l-.805 2.414a.25.25 0 0 0 .316.316l2.414-.805a.5.5 0 0 0 .196-.12l6.813-6.814z"/>
                                                <path fill-rule="evenodd" d="M1 13.5A1.5 1.5 0 0 0 2.5 15h11a1.5 1.5 0 0 0 1.5-1.5v-6a.5.5 0 0 0-1 0v6a.5.5 0 0 1-.5.5h-11a.5.5 0 0 1-.5-.5v-11a.5.5 0 0 1 .5-.5H9a.5.5 0 0 0 0-1H2.5A1.5 1.5 0 0 0 1 2.5v11z"/>
                                                </svg>
                                                </button>
                                                <button type="button" class="btn btn-outline-danger" style={{opacity: "70%"}} onClick={() => deleteStaff(val._id)}>
                                                <svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" fill="currentColor" class="bi bi-trash3" viewBox="0 0 16 16">
                                                <path d="M6.5 1h3a.5.5 0 0 1 .5.5v1H6v-1a.5.5 0 0 1 .5-.5ZM11 2.5v-1A1.5 1.5 0 0 0 9.5 0h-3A1.5 1.5 0 0 0 5 1.5v1H2.506a.58.58 0 0 0-.01 0H1.5a.5.5 0 0 0 0 1h.538l.853 10.66A2 2 0 0 0 4.885 16h6.23a2 2 0 0 0 1.994-1.84l.853-10.66h.538a.5.5 0 0 0 0-1h-.995a.59.59 0 0 0-.01 0H11Zm1.958 1-.846 10.58a1 1 0 0 1-.997.92h-6.23a1 1 0 0 1-.997-.92L3.042 3.5h9.916Zm-7.487 1a.5.5 0 0 1 .528.47l.5 8.5a.5.5 0 0 1-.998.06L5 5.03a.5.5 0 0 1 .47-.53Zm5.058 0a.5.5 0 0 1 .47.53l-.5 8.5a.5.5 0 1 1-.998-.06l.5-8.5a.5.5 0 0 1 .528-.47ZM8 4.5a.5.5 0 0 1 .5.5v8.5a.5.5 0 0 1-1 0V5a.5.5 0 0 1 .5-.5Z"/>
                                                </svg>
                                                </button>
                                                </div>
                                            </td>
                                        </tr>
                                        </>
                                    ):(
                                        <>

                                        </>
                                    )}
                                    </>
                                ):(
                                    <>
                                    <tr key={val._id}>
                                        <td>{val.name}</td>
                                        <td>{val.email}</td>
                                        <td>{val.age}</td>
                                        <td>{val.gender}</td>
                                        <td>{val.nic}</td>
                                        <td>{val.address}</td>
                                        <td>{val.mobile}</td>
                                        <td>{val.role}</td>
                                        <td>{val.research}</td>
                                        <td align="right" style={{width:'18px'}}>
                                            <div class="btn-group" role="group" aria-label="Basic mixed styles example">
                                            <button type="button" class="btn btn-outline-light" onClick={() => updateRole(val._id, val.role, "Staff member")}>
                                                Stf
                                            </button>
                                            <button type="button" class="btn btn-outline-light" onClick={() => updateRole(val._id, val.role, "Supervisor")}>
                                                Su
                                            </button>
                                            <button type="button" class="btn btn-outline-light" onClick={() => updateRole(val._id, val.role, "Co-supervisor")}>
                                                Co
                                            </button>
                                            <button type="button" class="btn btn-outline-primary" style={{opacity: "70%"}} onClick={() => passValues(val._id, val.name, val.email, val.age, val.gender, val.nic, val.address, val.mobile, val.password)}>
                                            <svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" fill="currentColor" class="bi bi-pencil-square" viewBox="0 0 16 16">
                                            <path d="M15.502 1.94a.5.5 0 0 1 0 .706L14.459 3.69l-2-2L13.502.646a.5.5 0 0 1 .707 0l1.293 1.293zm-1.75 2.456-2-2L4.939 9.21a.5.5 0 0 0-.121.196l-.805 2.414a.25.25 0 0 0 .316.316l2.414-.805a.5.5 0 0 0 .196-.12l6.813-6.814z"/>
                                            <path fill-rule="evenodd" d="M1 13.5A1.5 1.5 0 0 0 2.5 15h11a1.5 1.5 0 0 0 1.5-1.5v-6a.5.5 0 0 0-1 0v6a.5.5 0 0 1-.5.5h-11a.5.5 0 0 1-.5-.5v-11a.5.5 0 0 1 .5-.5H9a.5.5 0 0 0 0-1H2.5A1.5 1.5 0 0 0 1 2.5v11z"/>
                                            </svg>
                                            </button>
                                            <button type="button" class="btn btn-outline-danger" style={{opacity: "70%"}} onClick={() => deleteStaff(val._id)}>
                                            <svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" fill="currentColor" class="bi bi-trash3" viewBox="0 0 16 16">
                                            <path d="M6.5 1h3a.5.5 0 0 1 .5.5v1H6v-1a.5.5 0 0 1 .5-.5ZM11 2.5v-1A1.5 1.5 0 0 0 9.5 0h-3A1.5 1.5 0 0 0 5 1.5v1H2.506a.58.58 0 0 0-.01 0H1.5a.5.5 0 0 0 0 1h.538l.853 10.66A2 2 0 0 0 4.885 16h6.23a2 2 0 0 0 1.994-1.84l.853-10.66h.538a.5.5 0 0 0 0-1h-.995a.59.59 0 0 0-.01 0H11Zm1.958 1-.846 10.58a1 1 0 0 1-.997.92h-6.23a1 1 0 0 1-.997-.92L3.042 3.5h9.916Zm-7.487 1a.5.5 0 0 1 .528.47l.5 8.5a.5.5 0 0 1-.998.06L5 5.03a.5.5 0 0 1 .47-.53Zm5.058 0a.5.5 0 0 1 .47.53l-.5 8.5a.5.5 0 1 1-.998-.06l.5-8.5a.5.5 0 0 1 .528-.47ZM8 4.5a.5.5 0 0 1 .5.5v8.5a.5.5 0 0 1-1 0V5a.5.5 0 0 1 .5-.5Z"/>
                                            </svg>
                                            </button>
                                            </div>
                                        </td>
                                    </tr>
                                    </>
                                )}
                                
                                </>
                            )
                       })
                   }
               </tbody>
           </table>
        </>
    )

}