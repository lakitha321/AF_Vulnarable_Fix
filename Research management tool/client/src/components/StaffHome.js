import React, { useState, useEffect, useContext } from 'react';
import { UserContext } from "../App";

const StaffHome = () => {

  const {state1, dispatch} = useContext(UserContext);
  dispatch({type:"USER", payload:3})

  const name = localStorage.getItem("stfname");
  return (
    <div className="container my-5" style={{opacity:'90%', fontWeight:'100', color:'white'}}>
      <br/><br/><br/>
      <p style={{fontSize:'60px'}}>Welcome {name}....</p>
    </div>
  );
};

export default StaffHome;