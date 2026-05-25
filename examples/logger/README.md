# Using the Logs Distributor

A logs distributor (in **dist_logs.hpp**) is available in the DCT codebase. When enabled, a distributor is created that publishes in a **logs** subcollection. To enable logging, set the boolean variable *logging_* in dct_model.hpp (currently line 78) to **true**.  When logging, DCTmodel creates a DistLogs object and sets up a logs callback function (at *logsCb_*) that calls *DistLogs::publishLog()* method with a log message. This log message is inserted in a name, between the pubprefix (if any) and the timestamp and becomes the name of the **logs** publication (the method *prepends* the domain prefix in use, if any, and *appends* a timestamp) and the publication's content, if any.  DistTDVC and DistGkey are currently set up to use logging. DCTmodel explicitly sets the distributor's *logsCb_* to *DCTmodel::logsCb_*.  The **logs** publications' convention is to use the same prefix as for messages pubs (though this can be left off) then a field that identifies the calling module. The rest of the name identifies the event being logged and Content may be provided or left empty. It is expected that the log publication name between the Trust Domain's pub prefix and timestamp fields will be the log message.

The distributor method *logEvent*() is defined in dist.hpp but will have a derived method in a distributor that is using logging. Example usage of *logEvent*() is in dist_tdvc.hpp. The subname's first field is "tdvc" to show what module made the log, the second field indicates what type of TDVC event is being logged, the next two are identifiers from the member's identity cert, and the final one is the neighborhood size used for the last round's virtual clock computation. These publications in the **logs** collection can be extracted from a **dctwatch** output and the fields processed.. This use of **dctwatch** and postprocessing was used as an aide in debugging and developing DistTDVC. Example usage of *logEvent()* is also in dist_gkey.hpp, but this is included as a simple example only (the keymaker publishes a log when it gets a member request) and hasn't been used in debugging. For other DCT modules to use logging, they  need a logsCb_ variable and a logEvent() method. The recommended convention is the first field of the log message passed to logEvent() is an identifier for the calling module. Distributors that are using logging should have their *logsCb_* set in *DCTmodel::start()*.

## Application use of the log distributor

It is also possible to enable logging from applications and the examples/logs illustrates how this can be done. Applications access logging through their shims, first calling the mbps *setLogging*() method after an mbps has been created but before *connect*() is called (see log/exApp.cpp).

In applications using logging, the shim (e.g., *mbps*) calls *DCTmodel::setLogging()* before *DCTmodel::start()* is called. The *DCTmodel::logEvent()* method can be accessed by applications through their shim. The application can put whatever fields make a useful log message in string *s* and may add additional information that goes into a log publication's content field.

```
 in DCTmodel:
  void logEvent(std::string s, std::span<const uint8_t> content = {}) {
        logsCb_(s, content);
   }
 in application, make sure logging is enabled, insert after making mbps:
   cm.setLogging();
 in mbps, method application uses to log an event:
   void logEvent(std::string s, std::span<const uint8_t> content = {}) {
   		m_pb.logEvent(s, content);
   } 
 in application, this creates a log event with topic exApp/rcv
   cm.logEvent("exApp/rcv");
 in mbps, to log events within mbps
   void logMbpsEvent(std::string s, std::span<const uint8_t> content = {}) {
   	  m_pb.logEvent("mpbs"/s, content);
   }
```

The above methods can be used to publish log messages in the **logs** collection that can be captured with *dctwatch* and then processed. An application can also subscribe to **logs** publications in order to store and/or process them. Methods in DistLogs, DCTmodel, and mbps:

```
 in DistLogs:
     auto& subscribeLogs(std::string_view topic, SubCb&& cb) {
         return sync_.subscribe(crPrefix{appendToName(prefix_, topic)}, std::move(cb) );
     }
  and:
     auto& subscribeLogs(SubCb&& cb) {
        return sync_.subscribe(crPrefix{prefix_}, std::move(cb) );
     }
 in DCTmodel, the logs distributor (lgd_) is called:
     auto& subscribeLogs(std::string_view topic, SubCb&& cb) {
        lgd_->subscribeLogs(crPrefix{topic}, std::move(cb));
        return *this;
    }
 in mbps:   
     mbps& subscribeLogs(std::string_view topic, const logHndlr& mh)    {
 		    m_pb.subscribeLogs(topic, [this,lh](auto p) {receiveLog(p, lh);});
    		return *this;
     }
 in application, make sure logging is enabled, insert after making mbps:
     cm.setLogging();
 then set up subscriptions for topics or for all logs:
     cm.subscribeLogs("gkp", logRecv); // application must have a logRecv msgHndlr method
 or:
     cm.subscribeLogs(logRecv); // logRecv will get called for all logs publications
```

The application has to subscribe and provide a callback method that does the log processing and potentially *cm.setLogging*() if it's not known to be enabled in dct_model.hpp. There's no harm in calling setLogging() if it's already set.

## Possible future work

The logs distributor uses EdDSA signing so it can be created before group key distributors. If encrypted logs are desired, the possibility of changing the distributor's **sigmgr** once group keys are in place can be explored or just setting up logging later.