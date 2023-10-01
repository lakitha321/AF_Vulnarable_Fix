import React,{useState, useEffect, useContext} from "react";
import axios from "axios";

import { UserContext } from "../App";

export default function AdminHome(){

    const {state, dispatch} = useContext(UserContext);
    dispatch({type:"USER", payload:2})

    return(
        <>
        <h1>hi....</h1>
        </>
    )

}