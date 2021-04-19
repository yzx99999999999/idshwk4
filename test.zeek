@load base/frameworks/sumstats

event http_reply(c: connection, version: string, code: count, reason: string)
{
   SumStats::observe("response", SumStats::Key($host=c$id$orig_h), SumStats::Observation($num=1));
   if (code == 404) 
   {
        SumStats::observe("response404", SumStats::Key($host=c$id$orig_h), SumStats::Observation($num=1));
        SumStats::observe("responseUnique404", SumStats::Key($host=c$id$orig_h), SumStats::Observation($str=c$http$uri));
    }
}

event zeek_init()
    {
    local r_All = SumStats::Reducer($stream="response", $apply=set(SumStats::SUM));
    local r_404 = SumStats::Reducer($stream="response404", $apply=set(SumStats::SUM));
    local r_Unique_404 = SumStats::Reducer($stream="responseUnique404", $apply=set(SumStats::UNIQUE));
    SumStats::create([$name="Detect_http_scans",
                      $epoch=10min,
                      $reducers=set(r_All,r_404,r_Unique_404),
                      $epoch_result(ts: time, key: SumStats::Key, result: SumStats::Result) =
                        {
                        local r1 = result["response"];
                        local r2 = result["response404"];
                        local r3 = result["responseUnique404"];
                        if(r2$sum>2)
                        (
                           if(r2$sum / r1$sum > 0.2)
                           { 
                               if(r3$unique / r2$sum > 0.5)
                               {
                                 print fmt("%s is a scanner with %d scan attemps on %d urls", 
                        			key$host, r2$num, r3$hll_unique);
                               }
                           }
                        )
                    }]);
    }


