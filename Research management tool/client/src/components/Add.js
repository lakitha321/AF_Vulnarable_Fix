import React,{useState} from "react";
import axios from "axios";
import Header from "./Header";
import All from "./All";

export default function Add(){

    const [name, setName] = useState("");
    const [age, setAge] = useState("");
    const [gender, setGender] = useState("");

    function sendData(e){
        e.preventDefault();

        const newPerson = {
            name,
            age,
            gender
        }

        axios.post("http://localhost:8070/person/add", newPerson).then((res)=>{
            //Header('location:../public/index.html');
            alert(res.data);
            window.location.assign("/");
        }).catch((err)=>{
            alert(err);
        })

        // window.location.assign("/");
    }

    return(
        <div className="container my-5">
            <form onSubmit={sendData}>
                <div className="mb-3">
                    <label for="exampleInputEmail1" className="form-label">Name</label>
                    <input type="text" name="pName" className="form-control" id="exampleInputEmail1" aria-describedby="emailHelp" 
                    onChange={(e) => {
                        setName(e.target.value);
                    }} />
                </div>
                <div className="mb-3">
                    <label for="exampleInputPassword1" className="form-label">Age</label>
                    <input type="text" className="form-control" id="exampleInputPassword1" 
                    onChange={(e) => {
                        setAge(e.target.value);
                    }} />
                </div>
                <div className="mb-3">
                    <label for="exampleInputPassword1" className="form-label">Gender</label>
                    <input type="text" className="form-control" id="exampleInputPassword1" 
                    onChange={(e) => {
                        setGender(e.target.value);
                    }} />
                </div>
                <button type="submit" className="btn btn-primary">Submit</button>
            </form>
        </div>
    )
}