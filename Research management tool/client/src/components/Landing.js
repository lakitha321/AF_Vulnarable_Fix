import React,{useState, useContext} from "react";
import {BrowserRouter as Router, Link} from 'react-router-dom';
import Card from "react-bootstrap/Card";

import { UserContext } from "../App";

function Landing() {

    const {state1, dispatch} = useContext(UserContext);
    dispatch({type:"USER", payload:0})

    return (
        <>
        <br/><br/><br/><br/><br/>
        <Card style={{ backgroundColor : 'transparent', width: '58rem',  height: '38rem', margin:"auto", opacity:"100%" }}>
        <Card.Body align="center">
            <p className="fs-1" style={{color:"white"}}>Research and Project Management</p><br/>
            <p className="fs-8" style={{color:"white"}}>Project descriptions provide the following details to the applicants: the problem the project will address, a set of goals for the project, the overall objectives for the project, as well as a project plan that describes the activities the members will undertake.  The project description also includes the location of the project, the length of the project, and any benefits you will receive while serving on the project.</p>
            <br/>
            <div class="d-grid gap-2 d-md-block">
            <Link to="/log"><button type="button" class="btn btn-warning" style={{width: '18rem'}}>Sign in</button></Link>&nbsp;&nbsp;&nbsp;
            <Link to="/sreg"><button type="button" class="btn btn-outline-warning" style={{width: '18rem'}}>Sign up</button></Link>
            </div><br/>
            <p className="fs-7" style={{color:"white"}}>If you already have an account click on "Sign in",<br/> if you don't have an account already then click on "Sign up"</p>
        </Card.Body>
        </Card>
        </>
    );
}
  
export default Landing;