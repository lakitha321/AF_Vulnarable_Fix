import React,{useState, useContext} from "react";
import axios from "axios";
import {BrowserRouter as Router, Link} from 'react-router-dom';
import { confirm } from "react-confirm-box";

import { UserContext } from "../App";

function Header(){

    var sid = localStorage.getItem("sid");
    var sname = localStorage.getItem("sname");
    var semail = localStorage.getItem("semail");
    var sage = localStorage.getItem("sage");
    var sgender = localStorage.getItem("sgender");
    var snic = localStorage.getItem("snic");
    var saddress = localStorage.getItem("saddress");
    var smobile = localStorage.getItem("smobile");
    var spassword = localStorage.getItem("spassword");
    var sgroupid = localStorage.getItem("sgroupid");

    var stfid = localStorage.getItem("stfid");
    var stfname = localStorage.getItem("stfname");
    var stfemail = localStorage.getItem("stfemail");
    var stfage = localStorage.getItem("stfage");
    var stfgender = localStorage.getItem("stfgender");
    var stfnic = localStorage.getItem("stfnic");
    var stfaddress = localStorage.getItem("stfaddress");
    var stfmobile = localStorage.getItem("stfmobile");
    var stfpassword = localStorage.getItem("stfpassword");
    var stfrole = localStorage.getItem("stfrole");
    var stfresearch = localStorage.getItem("stfresearch");

    var aid = localStorage.getItem("aid");
    var aname = localStorage.getItem("aname");
    var aemail = localStorage.getItem("aemail");
    var anic = localStorage.getItem("anic");
    var amobile = localStorage.getItem("amobile");
    var afirstpassword = localStorage.getItem("afirstpassword");
    var asecondpassword = localStorage.getItem("asecondpassword");

    const {state, dispatch} = useContext(UserContext);

    const deleteStudent = async () => {
        const result1 = await confirm("Are you sure do you want to delete your account?");
        if (result1) {
            const result2 = await confirm("Your account wil be permenantly deleted!!!");
            if(result2){
              axios.delete(`http://localhost:8070/student/delete/${sid}`).then((res) => {
                localStorage.setItem("sid", "");
                localStorage.setItem("sname", "");
                localStorage.setItem("semail", "");
                localStorage.setItem("sage", "");
                localStorage.setItem("sgender", "");
                localStorage.setItem("snic", "");
                localStorage.setItem("saddress", "");
                localStorage.setItem("smobile", "");
                localStorage.setItem("spassword", "");
                localStorage.setItem("sgroupid", "");
                alert(res.data);
              }).catch((err) => {
                  alert(err);
              });
              window.location.assign("/log");
            }
            
          }
    }

    function profile(){
        if(state == 1){
        return(
            <>
            <p className="fs-3">{sname}</p>
            <table style={{width: "100%"}}>
                <tr>
                    <td className="fs-7">NIC</td>
                    <td className="fs-7">{snic}</td>
                </tr>
                <tr>
                    <td className="fs-7">Email</td>
                    <td className="fs-7"><a href="">{semail}</a></td>
                </tr>
                <tr>
                    <td className="fs-7">Mobile</td>
                    <td className="fs-7">{smobile}</td>
                </tr>
                <tr>
                    <td className="fs-7">Age</td>
                    <td className="fs-7">{sage}</td>
                </tr>
                <tr>
                    <td className="fs-7">Address</td>
                    <td className="fs-7">{saddress}</td>
                </tr>
                <tr>
                    <td className="fs-7">Gender</td>
                    <td className="fs-7">{sgender}</td>
                </tr>
                <tr>
                    <td className="fs-7">Group</td>
                    <td className="fs-7">{sgroupid}</td>
                </tr>
            </table>
            <br/>
            <Link to="/supd">
            <button style={{width: "100%", opacity:"70%"}} type="button" className="btn btn-lg btn-primary" data-bs-dismiss="offcanvas" aria-label="Close">
            <svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" fill="currentColor" className="bi bi-pencil-square" viewBox="0 0 16 16">
              <path d="M15.502 1.94a.5.5 0 0 1 0 .706L14.459 3.69l-2-2L13.502.646a.5.5 0 0 1 .707 0l1.293 1.293zm-1.75 2.456-2-2L4.939 9.21a.5.5 0 0 0-.121.196l-.805 2.414a.25.25 0 0 0 .316.316l2.414-.805a.5.5 0 0 0 .196-.12l6.813-6.814z"/>
              <path fill-rule="evenodd" d="M1 13.5A1.5 1.5 0 0 0 2.5 15h11a1.5 1.5 0 0 0 1.5-1.5v-6a.5.5 0 0 0-1 0v6a.5.5 0 0 1-.5.5h-11a.5.5 0 0 1-.5-.5v-11a.5.5 0 0 1 .5-.5H9a.5.5 0 0 0 0-1H2.5A1.5 1.5 0 0 0 1 2.5v11z"/>
            </svg>
            &nbsp;&nbsp;
            Edit account
            </button></Link><br/><br/>
            <button style={{width: "100%", opacity:"70%"}} type="button" className="btn btn-lg btn-danger" data-bs-dismiss="offcanvas" aria-label="Close" onClick={deleteStudent}>
            <svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" fill="currentColor" className="bi bi-trash" viewBox="0 0 16 16">
              <path d="M5.5 5.5A.5.5 0 0 1 6 6v6a.5.5 0 0 1-1 0V6a.5.5 0 0 1 .5-.5zm2.5 0a.5.5 0 0 1 .5.5v6a.5.5 0 0 1-1 0V6a.5.5 0 0 1 .5-.5zm3 .5a.5.5 0 0 0-1 0v6a.5.5 0 0 0 1 0V6z"/>
              <path fill-rule="evenodd" d="M14.5 3a1 1 0 0 1-1 1H13v9a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V4h-.5a1 1 0 0 1-1-1V2a1 1 0 0 1 1-1H6a1 1 0 0 1 1-1h2a1 1 0 0 1 1 1h3.5a1 1 0 0 1 1 1v1zM4.118 4 4 4.059V13a1 1 0 0 0 1 1h6a1 1 0 0 0 1-1V4.059L11.882 4H4.118zM2.5 3V2h11v1h-11z"/>
            </svg>
            &nbsp;&nbsp;Delete account
            </button>
            </>
        )}
        else if(state == 2){
            return(
                <>
                <p className="fs-1">{aname}</p>
                <table style={{width: "100%"}}>
                    <tr>
                        <td className="fs-5">NIC</td>
                        <td className="fs-5">{anic}</td>
                    </tr>
                    <tr>
                        <td className="fs-5">Email</td>
                        <td className="fs-5"><a href="">{aemail}</a></td>
                    </tr>
                    <tr>
                        <td className="fs-5">Mobile</td>
                        <td className="fs-5">{amobile}</td>
                    </tr>
                </table>
                <br/>
                <Link to="/adminupdate">
                <button style={{width: "100%", opacity:"70%"}} type="button" className="btn btn-lg btn-primary" data-bs-dismiss="offcanvas" aria-label="Close">
                <svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" fill="currentColor" className="bi bi-pencil-square" viewBox="0 0 16 16">
                  <path d="M15.502 1.94a.5.5 0 0 1 0 .706L14.459 3.69l-2-2L13.502.646a.5.5 0 0 1 .707 0l1.293 1.293zm-1.75 2.456-2-2L4.939 9.21a.5.5 0 0 0-.121.196l-.805 2.414a.25.25 0 0 0 .316.316l2.414-.805a.5.5 0 0 0 .196-.12l6.813-6.814z"/>
                  <path fill-rule="evenodd" d="M1 13.5A1.5 1.5 0 0 0 2.5 15h11a1.5 1.5 0 0 0 1.5-1.5v-6a.5.5 0 0 0-1 0v6a.5.5 0 0 1-.5.5h-11a.5.5 0 0 1-.5-.5v-11a.5.5 0 0 1 .5-.5H9a.5.5 0 0 0 0-1H2.5A1.5 1.5 0 0 0 1 2.5v11z"/>
                </svg>
                Edit account
                </button></Link>
                </>
            )
        }

        else if(state == 3){
            return(
                <>
                <p className="fs-3">{stfname}</p>
                <table style={{width: "100%"}}>
                    <tr>
                        <td className="fs-7">NIC</td>
                        <td className="fs-7">{stfnic}</td>
                    </tr>
                    <tr>
                        <td className="fs-7">Email</td>
                        <td className="fs-7"><a href="">{stfemail}</a></td>
                    </tr>
                    <tr>
                        <td className="fs-7">Mobile</td>
                        <td className="fs-7">{stfmobile}</td>
                    </tr>
                    <tr>
                        <td className="fs-7">Age</td>
                        <td className="fs-7">{stfage}</td>
                    </tr>
                    <tr>
                        <td className="fs-7">Address</td>
                        <td className="fs-7">{stfaddress}</td>
                    </tr>
                    <tr>
                        <td className="fs-7">Gender</td>
                        <td className="fs-7">{stfgender}</td>
                    </tr>
                    <tr>
                        <td className="fs-7">Role</td>
                        <td className="fs-7">{stfrole}</td>
                    </tr>
                    <tr>
                        <td className="fs-7">R area</td>
                        <td className="fs-7">{stfresearch}</td>
                    </tr>
                </table>
                <br/>
                <Link to="/supd">
                <button style={{width: "100%", opacity:"70%"}} type="button" className="btn btn-lg btn-primary" data-bs-dismiss="offcanvas" aria-label="Close">
                <svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" fill="currentColor" className="bi bi-pencil-square" viewBox="0 0 16 16">
                  <path d="M15.502 1.94a.5.5 0 0 1 0 .706L14.459 3.69l-2-2L13.502.646a.5.5 0 0 1 .707 0l1.293 1.293zm-1.75 2.456-2-2L4.939 9.21a.5.5 0 0 0-.121.196l-.805 2.414a.25.25 0 0 0 .316.316l2.414-.805a.5.5 0 0 0 .196-.12l6.813-6.814z"/>
                  <path fill-rule="evenodd" d="M1 13.5A1.5 1.5 0 0 0 2.5 15h11a1.5 1.5 0 0 0 1.5-1.5v-6a.5.5 0 0 0-1 0v6a.5.5 0 0 1-.5.5h-11a.5.5 0 0 1-.5-.5v-11a.5.5 0 0 1 .5-.5H9a.5.5 0 0 0 0-1H2.5A1.5 1.5 0 0 0 1 2.5v11z"/>
                </svg>
                &nbsp;&nbsp;
                Edit account
                </button></Link><br/><br/>
                <button style={{width: "100%", opacity:"70%"}} type="button" className="btn btn-lg btn-danger" data-bs-dismiss="offcanvas" aria-label="Close" onClick={deleteStudent}>
                <svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" fill="currentColor" className="bi bi-trash" viewBox="0 0 16 16">
                  <path d="M5.5 5.5A.5.5 0 0 1 6 6v6a.5.5 0 0 1-1 0V6a.5.5 0 0 1 .5-.5zm2.5 0a.5.5 0 0 1 .5.5v6a.5.5 0 0 1-1 0V6a.5.5 0 0 1 .5-.5zm3 .5a.5.5 0 0 0-1 0v6a.5.5 0 0 0 1 0V6z"/>
                  <path fill-rule="evenodd" d="M14.5 3a1 1 0 0 1-1 1H13v9a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V4h-.5a1 1 0 0 1-1-1V2a1 1 0 0 1 1-1H6a1 1 0 0 1 1-1h2a1 1 0 0 1 1 1h3.5a1 1 0 0 1 1 1v1zM4.118 4 4 4.059V13a1 1 0 0 0 1 1h6a1 1 0 0 0 1-1V4.059L11.882 4H4.118zM2.5 3V2h11v1h-11z"/>
                </svg>
                &nbsp;&nbsp;Delete account
                </button>
                </>
            )
        }
    }

    const RenderMenu = () => {

        if(state == 1){
            return(
                <>
                    <td>
                        <Link to="/home" className="nav-link active" aria-current="page" style={{color: "white"}}>Home</Link>  
                    </td>
                    <td>
                        <Link to="/viewgroup" className="nav-link" aria-current="page" style={{color: "white"}}>Reserch group</Link>
                    </td>
                    <td>
                        <Link to="/studentpanel" className="nav-link" aria-current="page" style={{color: "white"}}>Panel</Link>
                    </td>
                    <td>
                        <Link to="/studentsubmissions" className="nav-link" aria-current="page" style={{color: "white"}}>Submissions</Link>
                    </td>
                    <td>
                        <Link to="/studentfiles" className="nav-link" aria-current="page" style={{color: "white"}}>Files</Link>
                    </td>
                    <td>
                        <button className="navbar-toggler" type="button" data-bs-toggle="offcanvas" data-bs-target="#offcanvasNavbar" aria-controls="offcanvasNavbar">
                            <svg xmlns="http://www.w3.org/2000/svg" style={{color: "white"}} width="24" height="24" fill="currentColor" className="bi bi-person-circle" viewBox="0 0 16 16">
                                <path d="M11 6a3 3 0 1 1-6 0 3 3 0 0 1 6 0z"/>
                                <path fill-rule="evenodd" d="M0 8a8 8 0 1 1 16 0A8 8 0 0 1 0 8zm8-7a7 7 0 0 0-5.468 11.37C3.242 11.226 4.805 10 8 10s4.757 1.225 5.468 2.37A7 7 0 0 0 8 1z"/>
                            </svg>
                        </button>
                    </td>
                </>
            )
        }
        else if(state == 2){
            return(
                <>
                    <td>
                        <Link to="/home" className="nav-link active" aria-current="page" style={{color: "white"}}>Home</Link>  
                    </td>
                    <td>
                        <Link to="/allstaff" className="nav-link" aria-current="page" style={{color: "white"}}>Staff</Link>
                    </td>
                    <td>
                        <Link to="/panel" className="nav-link" aria-current="page" style={{color: "white"}}>Panel</Link>
                    </td>
                    <td>
                        <Link to="/allstudents" className="nav-link" aria-current="page" style={{color: "white"}}>Students</Link>
                    </td>
                    <td>
                        <Link to="/admingrp" className="nav-link" aria-current="page" style={{color: "white"}}>Student groups</Link>
                    </td>
                    <td>
                        <Link to="/allsubmissions" className="nav-link" aria-current="page" style={{color: "white"}}>Submissions</Link>
                    </td>
                    <td>
                        <Link to="/submissions" className="nav-link" aria-current="page" style={{color: "white"}}>Files</Link>
                    </td>
                    <td>
                        <button className="navbar-toggler" type="button" data-bs-toggle="offcanvas" data-bs-target="#offcanvasNavbar" aria-controls="offcanvasNavbar">
                            <svg xmlns="http://www.w3.org/2000/svg" style={{color: "white"}} width="24" height="24" fill="currentColor" className="bi bi-person-circle" viewBox="0 0 16 16">
                                <path d="M11 6a3 3 0 1 1-6 0 3 3 0 0 1 6 0z"/>
                                <path fill-rule="evenodd" d="M0 8a8 8 0 1 1 16 0A8 8 0 0 1 0 8zm8-7a7 7 0 0 0-5.468 11.37C3.242 11.226 4.805 10 8 10s4.757 1.225 5.468 2.37A7 7 0 0 0 8 1z"/>
                            </svg>
                        </button>
                    </td>
                </>
            )
        }
        else if(state == 3){
            return(
                <>
                    <td>
                        <Link to="/stfhome" className="nav-link active" aria-current="page" style={{color: "white"}}>Home</Link>  
                    </td>
                    <td>
                        <Link to="/staffpanel" className="nav-link active" aria-current="page" style={{color: "white"}}>Panel</Link>  
                    </td>
                    <td>
                        <Link to="/staffrequests" className="nav-link" aria-current="page" style={{color: "white"}}>Requests</Link>
                    </td>
                    <td>
                        <Link to="/acceptedgrps" className="nav-link" aria-current="page" style={{color: "white"}}>Groups</Link>
                    </td>
                    <td>
                        <button className="navbar-toggler" type="button" data-bs-toggle="offcanvas" data-bs-target="#offcanvasNavbar" aria-controls="offcanvasNavbar">
                            <svg xmlns="http://www.w3.org/2000/svg" style={{color: "white"}} width="24" height="24" fill="currentColor" className="bi bi-person-circle" viewBox="0 0 16 16">
                                <path d="M11 6a3 3 0 1 1-6 0 3 3 0 0 1 6 0z"/>
                                <path fill-rule="evenodd" d="M0 8a8 8 0 1 1 16 0A8 8 0 0 1 0 8zm8-7a7 7 0 0 0-5.468 11.37C3.242 11.226 4.805 10 8 10s4.757 1.225 5.468 2.37A7 7 0 0 0 8 1z"/>
                            </svg>
                        </button>
                    </td>
                </>
            )
        }
        else{
            return(
                <>
                    <td>
                        <Link to="/" className="nav-link" aria-current="page" style={{color: "white"}}>Home</Link>
                    </td>
                    <td>
                        <Link to="/log" className="nav-link" aria-current="page" style={{color: "white"}}>Sign in</Link>
                    </td>
                    <td>
                        <Link to="/sreg" className="nav-link" aria-current="page" style={{color: "white"}}>Sign up</Link>
                    </td>
                </>
            )
        }
        
    }

    return(
        <nav className="navbar navbar-dark bg-dark fixed-top">
            <div className="container-fluid">
                <a className="navbar-brand">Project portal</a>
                <table>
                    <tr>

                        <RenderMenu />
                        
                    </tr>
                </table>
                <div className="offcanvas offcanvas-end" tabindex="-1" id="offcanvasNavbar" aria-labelledby="offcanvasNavbarLabel">
                <div className="offcanvas-header">
                    <h5 className="offcanvas-title" id="offcanvasNavbarLabel">My Profile</h5>
                    <button type="button" className="btn-close text-reset" data-bs-dismiss="offcanvas" aria-label="Close"></button>
                </div>
                <div className="offcanvas-body">
                    <div align="center">
                    <img style={{width: "250px", opacity:"30%"}} src="https://www.kindpng.com/picc/m/495-4952535_create-digital-profile-icon-blue-user-profile-icon.png"></img>
                    </div>
                    <hr/>
                    {profile()}
                </div>
                </div>
            </div>
        </nav>
    )
}

export default Header;