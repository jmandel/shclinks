import React from "react";
import App from "./App";
import Client from "./Client";
import { BrowserRouter as Router, Switch, Route, Link } from "react-router-dom";

export default (
  <Router>
    <Switch>
      <Route exact path="/">
        <App />
      </Route>
      <Route path="/client">
        <Client />
      </Route>
    </Switch>
  </Router>
);
