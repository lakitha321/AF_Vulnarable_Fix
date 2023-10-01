import React, { useState, useEffect, useContext } from 'react';
import { UserContext } from "../App";

const FilesList = () => {

  const {state1, dispatch} = useContext(UserContext);
  dispatch({type:"USER", payload:1})

  const name = localStorage.getItem("sname");
  return (
    <div className="container my-5" style={{opacity:'90%', fontWeight:'100', color:'white'}}>
      <br/><br/><br/>
      <p style={{fontSize:'60px'}}>Welcome {name}....</p>
      <br/>
      <br/>
      <p className='fs-3'>Check your submissions</p>
      <hr/>
      <p>You can view your submissions at any time by logging into your account and clicking on the Submissions link at the navigation bar at the top left of the page:</p>
      <br/>
        <button type="button" class="btn btn-outline-success" style={{opacity: "90%", width: '20rem'}}>
          Click here to view submissions
        </button>
        <br/>
        <br/>
      <br/>
      <br/>
      <br/>
      <p className='fs-3'>Check the notices provided</p>
      <hr/>
      <p>Make sure to check the provided notices daily!!!</p>
      <br/>
        <button type="button" class="btn btn-outline-primary" style={{opacity: "90%", width: '20rem'}}>
          Click here to view the notices provided
        </button>
        <br/>
        <br/>
      <br/>
      <br/>
      <br/>
      <p className='fs-3'>View group details</p>
      <hr/>
      <p>In its most common form, the three tiers are called presentation, application and storage, in this order.</p>
      <br/>
        <button type="button" class="btn btn-outline-danger" style={{opacity: "90%", width: '20rem'}}>
          Click here to view the group details
        </button>
        <br/>
        <br/>
      <br/>
      <br/>
      <br/>
      <p className='fs-3'>About</p>
      <hr/>
      <p className='fs-6'>A web application is application software that runs on a web server, unlike computer-based software<br/> programs that are run locally on the operating system (OS) of the device. Web applications are <br/>accessed by the user through a web browser with an active network connection. These applications are programmed using a<br/> client–server modeled structure—the user ("client") is provided services through an off-site server that is hosted by a third-party.<br/> Examples of commonly-used web applications include: web-mail, online retail sales, online banking, and online auctions.</p>
      <p>Applications are usually broken into logical chunks called "tiers", where every tier is assigned a role. Traditional applications consist<br/> only of 1 tier, which resides on the client machine, but web applications lend themselves to an n-tiered approach by nature. Though many variations are possible,<br/> the most common structure is the three-tiered application. In its most common form, the three tiers are called presentation, application and storage, in this order. <br/>A web browser is the first tier (presentation), an engine using some dynamic Web content technology <br/>(such as ASP, CGI, ColdFusion, Dart, JSP/Java, Node.js, PHP, Python or Ruby on Rails) is the middle tier (application logic), and a database is the third tier (storage).<br/> The web browser sends requests to the middle tier, which services them by making queries and updates against the database and generates<br/> a user interface.
        For more complex applications, a 3-tier solution may fall short, and it may be beneficial to use an n-tiered approach,<br/></p>
      <p>where the greatest benefit is breaking the business logic, which resides on the application tier, into a more fine-grained model. Another benefit<br/> may be adding an integration tier that separates the data tier from the rest of tiers by providing an easy-to-use interface to access the data. <br/>For example, the client data would be accessed by calling a "list_clients()" function instead of making an SQL query directly<br/> against the client table on the database. This allows the underlying database to be replaced without making any<br/> change to the other tiers.
        There are some who view a web application as a two-tier architecture. This can be a "smart" client that performs all the <br/>work and queries a "dumb" server, or a "dumb" client that relies on a "smart" server. The client would handle the<br/> presentation tier, the server would have the database (storage tier), and the business logic (application tier)<br/> would be on one of them or on both. While this increases the scalability of the applications and separates the <br/>display and the database, it still doesn't allow for true specialization of layers, so most applications will outgrow this model</p>
    </div>
  );
};

export default FilesList;