#include <yaml.h>
#include <robin_hood.h>

int loadConfig(robin_hood::unordered_flat_map<string, string> &config_data)
{
    yaml_parser_t parser;
    yaml_event_t event;
    int done = 0;
    /* Create the Parser object. */
    yaml_parser_initialize(&parser);

    /* Set a file input. */
    FILE *input = fopen("../config/trade_engine.yaml", "rb");
    yaml_parser_set_input_file(&parser, input);
    int level = 0;
    string key, key1, key2, key3, key4;
    string val;
    bool is_key = true;
    char buf[256];
    /* Read the event sequence. */
    while (!done)
    {

        /* Get the next event. */
        if (!yaml_parser_parse(&parser, &event))
            goto error;
        switch (event.type)
        {
        case YAML_SCALAR_EVENT:
            memcpy(buf, event.data.scalar.value, event.data.scalar.length);
            buf[event.data.scalar.length] = 0;
            // spdlog::info("[main]>>> scalar.value = {}, length={}, quote_implicit= {}, plain_implicit={}, type={}", buf, event.data.scalar.length, event.data.scalar.quoted_implicit, event.data.scalar.plain_implicit, (int)event.data.scalar.style);
            if (is_key)
            {
                switch (level)
                {
                case 1:
                    key1 = string(buf);
                    key2 = "", key3 = "", key4 = "";
                    key = key1;
                    break;
                case 2:
                    key2 = string(buf);
                    key3 = "", key4 = "";
                    key = key1 + "." + key2;
                    break;
                case 3:
                    key3 = string(buf);
                    key4 = "";
                    key = key1 + "." + key2 + "." + key3;
                    break;
                case 4:
                    key4 = string(buf);
                    key = key1 + "." + key2 + "." + key3 + "." + key4;
                    break;
                }
                is_key = false;
            }
            else
            {
                val = string(buf);
                spdlog::info("[main] ~~~~~~~~~ key={} valule={}", key, val);
                config_data.emplace(key, val);
                is_key = true;
            }
            break;
        case YAML_ALIAS_EVENT:
            //printf(">>> alias.anchor = %s, tag=%s,  implicit=%d \n", event.data.alias.anchor);
            break;
        case YAML_SEQUENCE_START_EVENT:
            //printf(">>> sequence_start.anchor = %s, tag=%s,  implicit=%d  \n", event.data.sequence_start.anchor, event.data.sequence_start.tag, event.data.sequence_start.implicit);
            break;
        case YAML_MAPPING_START_EVENT:
            ++level;
            is_key = true;
            //printf(">>> mapping_start.anchor = %s, tag=%s,  implicit=%d \n", event.data.mapping_start.anchor, event.data.mapping_start.tag, event.data.mapping_start.implicit);
            break;
        case YAML_MAPPING_END_EVENT:
            --level;
            // printf(">>> mapping_end \n");
            break;
        case YAML_STREAM_END_EVENT:
            done = (event.type == YAML_STREAM_END_EVENT);
            break;
        default:
            break;
        }
        /* The application is responsible for destroying the event object. */
        yaml_event_delete(&event);
    }
    

    /* Destroy the Parser object. */
    yaml_parser_delete(&parser);

    return 0;

/* On error. */
error:

    /* Destroy the Parser object. */
    yaml_parser_delete(&parser);
    return 1;
}


int main()
{
       robin_hood::unordered_flat_map<string, string> config_data;
        loadConfig(config_data); 
        string ip1 = config_data["md.group1.ip"];
        int port1 = atoi(config_data["md.group1.port"].c_str());
        return 0;
        
}
