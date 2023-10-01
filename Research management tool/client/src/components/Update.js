import React,{useState} from "react";
import axios from "axios";
import Header from "./Header";
import All from "./All";

export default function Update(){

    var cID = localStorage.getItem("id");
    var cName = localStorage.getItem("name");
    var cAge = localStorage.getItem("age");
    var cGender = localStorage.getItem("gender");

    const [name, setName] = useState(cName);
    const [age, setAge] = useState(cAge);
    const [gender, setGender] = useState(cGender);

    function sendData(e){

        e.preventDefault();

        const newPerson = {
            name,
            age,
            gender
        }

        axios.put(`http://localhost:8070/person/update/${cID}`, newPerson).then(()=>{
            //Header('location:../public/index.html');
        }).catch((err)=>{
            alert(err);
        })

        window.location.assign("/");
    }

    return(
        <div className="container my-5">
            <form onSubmit={sendData}>
                <div className="mb-3">
                    <label for="exampleInputEmail1" className="form-label">Name</label>
                    <input type="text" name="pName" className="form-control" id="exampleInputEmail1" defaultValue={cName} aria-describedby="emailHelp" 
                    onChange={(e) => {
                        setName(e.target.value);
                    }} />
                </div>
                <div className="mb-3">
                    <label for="exampleInputPassword1" className="form-label">Age</label>
                    <input type="text" className="form-control" id="exampleInputPassword1" defaultValue={cAge}
                    onChange={(e) => {
                        setAge(e.target.value);
                    }} />
                </div>
                <div className="mb-3">
                    <label for="exampleInputPassword1" className="form-label">Gender</label>
                    <input type="text" className="form-control" id="exampleInputPassword1" defaultValue={cGender}
                    onChange={(e) => {
                        setGender(e.target.value);
                    }} />
                </div>
                <button type="submit" className="btn btn-primary">Update</button>
            </form>
        </div>
    )
}